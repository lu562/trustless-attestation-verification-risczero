// server.rs
use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use warp::Filter;

use attestation::{SEV_ATTESTATION_ELF, SEV_ATTESTATION_ID};
use proof_aggregation::{SEV_ATTESTATION_AGGREGATION_ELF, SEV_ATTESTATION_AGGREGATION_ID};
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};

use anyhow::{anyhow, Error, Result};
use base64::engine::general_purpose;
use base64::Engine;
use clap::{Parser, ValueEnum};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use uuid::Uuid;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Deserializer, Serialize};

use sev::firmware::guest::AttestationReport;
use sev::parser::ByteParser;

#[derive(Debug)]
struct MyRejection(Error);
impl warp::reject::Reject for MyRejection {}

#[derive(Clone)]
pub struct AppState {
    pub data_dir: PathBuf,
    pub receipts_dir: PathBuf,
    pub aggregated_receipt_path: PathBuf,
    pub task_map: Arc<Mutex<HashMap<String, TaskStatus>>>,
    pub task_handles: Arc<Mutex<HashMap<String, JoinHandle<()>>>>,
}

#[derive(Deserialize)]
pub struct AttestationRequest {
    #[serde(deserialize_with = "base64_deserialize")]
    pub report: Vec<u8>,

    #[serde(deserialize_with = "base64_deserialize")]
    pub vcek: Vec<u8>,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct Risc0Proof {
    /// The zkVM receipt.
    pub receipt: Receipt,
    /// The zkVM proof.
    pub image_id: [u32; 8],
}

fn base64_deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = <std::string::String as serde::Deserialize>::deserialize(deserializer)?;
    base64::engine::general_purpose::STANDARD
        .decode(&s)
        .map_err(serde::de::Error::custom)
}

#[derive(Deserialize)]
pub struct VerifyRequest {
    #[serde(deserialize_with = "base64_deserialize")]
    pub proof: Vec<u8>,
}

#[derive(Debug, Serialize, Clone)]
pub enum TaskState {
    Pending,
    Running,
    Success(Vec<u8>),
    Failed(String),
}

#[derive(Debug, Serialize, Clone)]
pub struct TaskStatus {
    pub state: TaskState,
}

fn run_verify(input_path: &str) -> Result<()> {
    let proof = fs::read(input_path)?;
    let proof = borsh::from_slice::<Risc0Proof>(&proof)?;

    proof.receipt.verify(proof.image_id)?;

    Ok(())
}

fn run_sev_attestation(report_path: &str, vcek_path: &str, output_path: &str) -> Result<()> {
    let report_raw = fs::read(report_path)?;
    let pem_data = fs::read_to_string(vcek_path)?;
    let parsed_report = AttestationReport::from_bytes(&report_raw)?;

    let env = ExecutorEnv::builder()
        .write(&(&parsed_report, pem_data.as_bytes()))
        .unwrap()
        .build()
        .unwrap();

    let prover = default_prover();

    println!("trying to prove...");

    let receipt = prover.prove(env, SEV_ATTESTATION_ELF).unwrap().receipt;

    println!("writing proof...");

    write_proof(&receipt, &SEV_ATTESTATION_ID, output_path)
}

fn run_sev_attestation_aggregation(input_path: &str, output_path: &str) -> Result<()> {
    // Extract *all* receipts from the specified file.
    let receipts = fs::read_dir(input_path)?
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let path = entry.path();
            let journal = fs::read(path).ok()?;
            Some(borsh::from_slice::<Receipt>(&journal).ok()?)
        })
        .collect::<Vec<_>>();

    let env = ExecutorEnv::builder().write(&receipts)?.build()?;
    let prover = default_prover();
    // Produce a receipt by proving the specified ELF binary.
    println!("trying to prove...");

    let receipt = prover.prove(env, SEV_ATTESTATION_AGGREGATION_ELF)?.receipt;

    println!("writing proof...");

    write_proof(&receipt, &SEV_ATTESTATION_AGGREGATION_ID, output_path)
}

fn write_proof(receipt: &Receipt, image_id: &[u32; 8], output_path: &str) -> Result<()> {
    let proof = Risc0Proof {
        receipt: receipt.clone(),
        image_id: *image_id,
    };
    let proof = borsh::to_vec(&proof).map_err(|e| anyhow!(e))?;

    fs::write(output_path, &proof).map_err(|e| anyhow!(e))
}

fn with_state(
    state: Arc<AppState>,
) -> impl Filter<Extract = (Arc<AppState>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || state.clone())
}

pub async fn run_server(addr: String) -> Result<()> {
    let data_dir = PathBuf::from("server_temp");
    let receipts_dir = PathBuf::from("receipts_storage");
    let aggregated_receipt_path = PathBuf::from("aggregated_receipt.rcpt");
    let task_map = Arc::new(Mutex::new(HashMap::new()));
    let task_handles = Arc::new(Mutex::new(HashMap::new()));

    tokio::fs::create_dir_all(&data_dir).await?;
    tokio::fs::create_dir_all(&receipts_dir).await?;

    let state = Arc::new(AppState {
        data_dir,
        receipts_dir,
        aggregated_receipt_path,
        task_map,
        task_handles,
    });

    // POST /attestation
    let attestation_route = warp::post()
        .and(warp::path("attestation"))
        .and(warp::body::json())
        .and(with_state(state.clone()))
        .and_then(handle_attestation);

    // POST /aggregation
    let aggregation_route = warp::post()
        .and(warp::path("aggregation"))
        .and(with_state(state.clone()))
        .and_then(handle_aggregation);

    let attestation_status_route = warp::get()
        .and(warp::path!("attestation" / "status" / String))
        .and(with_state(state.clone()))
        .and_then(handle_attestation_status);

    // POST /verify
    let verify_route = warp::post()
        .and(warp::path("verify"))
        .and(warp::body::json())
        .and_then(handle_verify);

    let kill_task_route = warp::delete()
        .and(warp::path!("attestation" / "kill" / String))
        .and(with_state(state.clone()))
        .and_then(handle_kill_task);

    let health_route = warp::path("health")
        .and(warp::get())
        .map(|| warp::reply::with_status("OK\n", warp::http::StatusCode::OK));

    let routes = attestation_route
        .or(attestation_status_route)
        .or(aggregation_route)
        .or(verify_route)
        .or(kill_task_route)
        .or(health_route)
        .with(warp::log("server"));

    println!("HTTP server running on http://{}", addr);
    let socket_addr: SocketAddr = addr.parse().expect("Invalid address");
    warp::serve(routes).run(socket_addr).await;

    Ok(())
}

async fn handle_attestation(
    body: AttestationRequest,
    state: Arc<AppState>,
) -> Result<impl warp::Reply, warp::Rejection> {
    let job_id = Uuid::new_v4().to_string();
    let job_id_cloned = job_id.clone();
    {
        let mut map = state.task_map.lock().await;
        map.insert(
            job_id.clone(),
            TaskStatus {
                state: TaskState::Pending,
            },
        );
    }
    let data_dir = state.data_dir.clone();
    let receipts_dir = state.receipts_dir.clone();
    let task_map = state.task_map.clone();
    let handle = tokio::spawn(async move {
        {
            let mut map = task_map.lock().await;
            if let Some(task) = map.get_mut(&job_id_cloned) {
                task.state = TaskState::Running;
            }
        }
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let report_path = data_dir.join(format!("report_{}.bin", timestamp));
        let vcek_path = data_dir.join(format!("vcek_{}.pem", timestamp));
        let receipt_path = data_dir.join(format!("receipt_{}.rcpt", timestamp));
        let receipt_path_cloned = receipt_path.clone();
        let permanent_receipt_path = receipts_dir.join(format!("receipt_{}.rcpt", timestamp));
        if let Err(e) = tokio::fs::write(&report_path, &body.report).await {
            let mut map = task_map.lock().await;
            if let Some(task) = map.get_mut(&job_id_cloned) {
                task.state = TaskState::Failed(format!("Failed to save report: {}", e));
            }
            return;
        }
        if let Err(e) = tokio::fs::write(&vcek_path, &body.vcek).await {
            let mut map = task_map.lock().await;
            if let Some(task) = map.get_mut(&job_id_cloned) {
                task.state = TaskState::Failed(format!("Failed to save VCEK: {}", e));
            }
            return;
        }
        let res = tokio::task::spawn_blocking(move || {
            run_sev_attestation(
                report_path.to_str().unwrap(),
                vcek_path.to_str().unwrap(),
                receipt_path_cloned.to_str().unwrap(),
            )
        })
        .await;
        match res {
            Ok(Ok(())) => match tokio::fs::read(&receipt_path).await {
                Ok(proof_data) => {
                    let _ = tokio::fs::copy(&receipt_path, &permanent_receipt_path).await;
                    let mut map = task_map.lock().await;
                    if let Some(task) = map.get_mut(&job_id_cloned) {
                        task.state = TaskState::Success(proof_data);
                    }
                }
                Err(e) => {
                    let mut map = task_map.lock().await;
                    if let Some(task) = map.get_mut(&job_id_cloned) {
                        task.state = TaskState::Failed(format!("Failed to read proof: {}", e));
                    }
                }
            },
            Ok(Err(e)) => {
                let mut map = task_map.lock().await;
                if let Some(task) = map.get_mut(&job_id_cloned) {
                    task.state = TaskState::Failed(format!("Proof generation failed: {}", e));
                }
            }
            Err(e) => {
                let mut map = task_map.lock().await;
                if let Some(task) = map.get_mut(&job_id_cloned) {
                    task.state = TaskState::Failed(format!("Task join error: {}", e));
                }
            }
        }
    });

    {
        let mut handles = state.task_handles.lock().await;
        handles.insert(job_id.clone(), handle);
    }

    Ok(warp::reply::json(&serde_json::json!({
        "job_id": job_id,
        "status": "pending"
    })))
}

async fn handle_attestation_status(
    job_id: String,
    state: Arc<AppState>,
) -> Result<Box<dyn warp::Reply + Send>, warp::Rejection> {
    let map = state.task_map.lock().await;
    if let Some(task) = map.get(&job_id) {
        let resp = match &task.state {
            TaskState::Pending => serde_json::json!({ "status": "pending" }),
            TaskState::Running => serde_json::json!({ "status": "running" }),
            TaskState::Success(proof_data) => {
                let proof_b64 = general_purpose::STANDARD.encode(proof_data);
                serde_json::json!({ "status": "success", "proof": proof_b64 })
            }
            TaskState::Failed(err_msg) => {
                serde_json::json!({ "status": "failed", "error": err_msg })
            }
        };
        Ok(Box::new(warp::reply::json(&resp)))
    } else {
        Ok(Box::new(warp::reply::with_status(
            warp::reply::json(&serde_json::json!({ "error": "Job ID not found" })),
            warp::http::StatusCode::NOT_FOUND,
        )))
    }
}

async fn handle_aggregation(state: Arc<AppState>) -> Result<impl warp::Reply, warp::Rejection> {
    let receipts_dir = state.receipts_dir.clone();
    let aggregated_receipt_path = state.aggregated_receipt_path.clone();
    let aggregated_receipt_path_clone = aggregated_receipt_path.clone();
    let result = tokio::task::spawn_blocking(move || {
        run_sev_attestation_aggregation(
            receipts_dir.to_str().unwrap(),
            aggregated_receipt_path.to_str().unwrap(),
        )
    })
    .await
    .unwrap();
    match result {
        Ok(_) => {
            let proof_data = tokio::fs::read(&aggregated_receipt_path_clone)
                .await
                .map_err(|e| warp::reject::custom(MyRejection(anyhow::Error::new(e))))?;
            Ok(warp::reply::with_header(
                warp::reply::with_status(proof_data, warp::http::StatusCode::OK),
                "Content-Type",
                "application/octet-stream",
            ))
        }
        Err(e) => {
            let err_msg = format!("Proof aggregation failed: {}", e);
            let err_bytes = err_msg.into_bytes();

            Ok(warp::reply::with_header(
                warp::reply::with_status(err_bytes, warp::http::StatusCode::INTERNAL_SERVER_ERROR),
                "Content-Type",
                "text/plain; charset=utf-8",
            ))
        }
    }
}

async fn handle_verify(body: VerifyRequest) -> Result<impl warp::Reply, warp::Rejection> {
    let proof = match borsh::from_slice::<Risc0Proof>(&body.proof) {
        Ok(p) => p,
        Err(e) => {
            let err_msg = format!("Failed to deserialize proof: {}", e);
            return Ok(warp::reply::with_status(
                err_msg,
                warp::http::StatusCode::BAD_REQUEST,
            ));
        }
    };

    let verify_result = tokio::task::spawn_blocking(move || proof.receipt.verify(proof.image_id))
        .await
        .map_err(|e| warp::reject::custom(MyRejection(anyhow::Error::new(e))))?;

    match verify_result {
        Ok(_) => Ok(warp::reply::with_status(
            "true\n".to_string(),
            warp::http::StatusCode::OK,
        )),
        Err(e) => {
            let err_msg = format!("Proof verification failed: {}", e);
            Ok(warp::reply::with_status(
                err_msg,
                warp::http::StatusCode::BAD_REQUEST,
            ))
        }
    }
}

async fn handle_kill_task(
    job_id: String,
    state: Arc<AppState>,
) -> Result<impl warp::Reply, warp::Rejection> {
    let mut handles = state.task_handles.lock().await;
    if let Some(handle) = handles.remove(&job_id) {
        handle.abort();

        let mut map = state.task_map.lock().await;
        if let Some(task) = map.get_mut(&job_id) {
            task.state = TaskState::Failed("Task aborted by user".to_string());
        }

        Ok(warp::reply::with_status(
            format!("Task {} aborted", job_id),
            warp::http::StatusCode::OK,
        ))
    } else {
        Ok(warp::reply::with_status(
            format!("Task {} not found or already completed", job_id),
            warp::http::StatusCode::NOT_FOUND,
        ))
    }
}
