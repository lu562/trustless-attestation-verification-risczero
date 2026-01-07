# Trustless Attestation Verification using RISC Zero zkVM

This project implements a trustless attestation system for AMD SEV-SNP using Risc-Zero. It allows for remote attestation verification in a client-server architecture, where the server generates proofs based on SEV reports and VCEK certificates, and clients can verify these proofs.

## Prerequisites

- Rust 1.85 or later
- RISC Zero toolchain (installed via `rzup`)
- AMD SEV-SNP-compatible hardware (for generating attestation evidence) (You can also use sample inputs provided in this repo for testing)

## Installation

1. Install the RISC Zero toolchain:

```bash
curl -L https://raw.githubusercontent.com/risc0/risc0/main/tools/install/install.sh | bash
source ~/.bashrc  # or restart your terminal
rzup install
```

2. Clone the repository:

```bash
git clone https://github.com/tiktok-privacy-innovation/trustless-attestation-verification-risczero.git
cd trustless-attestation-verification-risczero
```

3. Build the project:

```bash
cargo build --release
```

## Usage

We build this project with a client-server architecture. The server is responsible for running attestation verfication and proof generation, while the client provides attestation evidences to the server.

The application supports several modes of operation, controlled via command-line arguments:

### Server Operations

Run the server with default IP 127.0.0.1 and port number 8088

```bash
./target/release/tavern
```
If you want to run the server with a customized IP and port number, use the following command

```bash
./target/release/tavern --ip [your-ip-address] --port [your-port]
```

### Client Operations

We provide sample inputs for testing purpose in the folder `samples`.

#### Send an Attestation Request

```bash
curl -v -i -X POST http://127.0.0.1:8088/attestation   -H "Content-Type: application/json" -d @samples/input.json -o response.txt
```

This sends an HTTP attestation request to the server with the specified report and VCEK certificate. If you start the server with customed IP address and port, please adjust the request address accordingly.

After the request, the server will run proof verification and it might take a lot of time. The server will return a job ID to the client stored in `response.txt`, so that client can use it to query the job status and get proof result if the task is completed.

If you have access to RiscZero's online proving service Bonsai, you can enable it by setting up the environment variables before running the server. The proof generation takes around 30 seconds with Bonsai, and it may takes ~10-30 minutes in a normal machine.


#### Query Task Status


```bash
curl -s http://127.0.0.1:8088/attestation/status/[YOUR_JOB_ID]
```
Please replace [YOUR_JOB_ID] with the job ID you get from the previous command.
This polls the remote attestation status, if you see the status is "completed", run the following command to get the proof:

```bash
curl -s http://127.0.0.1:8088/attestation/status/[YOUR_JOB_ID] > receipt.json
```

#### Verify the Proof Remotely
You can encapsulate the proof with a json and sent it to the server for remote verification:

```bash
curl -v -i -X POST http://127.0.0.1:8088/verify   -H "Content-Type: application/json" -d @samples/receipt.json
```
#### Verify the Proof Locally
The client can also verify the proof locally using the binary "verify":

```bash
./target/release/verify --proof-path receipt.json
```

#### Unit Test

```bash
cargo test
```

## License

See the [LICENSE](LICENSE) for details.

## Acknowledgements

We would like to acknowledge the following projects that this implementation builds upon:
- [**snpguest**](https://github.com/virtee/snpguest)

See the [NOTICE](NOTICE) for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
