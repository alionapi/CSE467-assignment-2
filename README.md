# CSE467-assignment-2
CSE467: Computer Security | Spring 2026 | PKI/TLS



This project implements a simplified TLS interception system using OpenSSL. The system consists of a TLS client, an intercepting proxy, and a server, demonstrating how man-in-the-middle proxying operates and how it can affect end-to-end security guarantees.

The proxy inspects application-layer data, removes occurrences of a specific keyword, and forwards the modified content over a separate TLS connection.

## Features

* TLS client implementation using OpenSSL
* TLS interception proxy
* Support for TLS 1.2 and TLS 1.3
* Certificate-based authentication
* Digital signature verification
* Application-layer content modification
* Exact byte transmission and reception handling
* Network byte order support

## Repository Structure

```text
.
├── CSE467_assignment_2.pdf   # Assignment specification
├── Makefile                  # Build configuration
├── README.md                 # Repository documentation
├── client.c                  # TLS client implementation
├── proxy.c                   # TLS interception proxy
├── gen_certs.sh              # Certificate generation script
├── input.txt                 # Sample input file
```

## Components

### Client

The client:

* Establishes a TLS connection to either the server or proxy
* Supports TLS 1.2 and TLS 1.3
* Loads multiple trusted root CA certificates
* Sends file contents using the custom application protocol
* Extracts the peer certificate and public key
* Verifies digital signatures on server responses
* Detects whether communication passed through an interception proxy

### Proxy

The proxy:

* Accepts incoming TLS connections
* Establishes a separate TLS connection to the server
* Supports TLS 1.2 on both sides
* Intercepts application-layer data
* Removes all occurrences of `"stopword"`
* Updates protocol length fields accordingly
* Transparently relays server responses

## Communication Protocol

### Client → Server / Proxy

```text
[4-byte file length]
[file contents]
```

### Server → Client

```text
[4-byte message length]
["OK"]
[4-byte signature length]
[signature bytes]
```

All multi-byte integers are transmitted in network byte order.

## Security Concepts

The project demonstrates:

* Public Key Infrastructure (PKI)
* Certificate Authorities (CA)
* TLS handshakes
* Certificate validation
* Digital signatures
* Public key extraction
* TLS interception
* Man-in-the-middle proxying
* End-to-end security guarantees

## Building

Compile the project with:

```bash
make
```

This generates:

```text
client
proxy
```

## Running

### Generate Certificates

```bash
./gen_certs.sh
```

### Run the Proxy

```bash
./proxy certs/proxy.crt certs/proxy.key certs/ca_server.pem 8443 127.0.0.1 9443
```

### Connect Directly to the Server

```bash
./client localhost 9443 certs/ca_bundle.pem input.txt
```

### Connect Through the Proxy

```bash
./client localhost 8443 certs/ca_bundle.pem input.txt
```

## Main Source Files

### client.c

Implements:

* TLS connection establishment
* Certificate validation
* Message transmission
* Signature verification
* Proxy detection logic

### proxy.c

Implements:

* TLS interception
* Bidirectional forwarding
* Content modification
* Protocol reconstruction

### gen_certs.sh

Generates certificates and certificate authorities used for testing.

## Technologies

* C
* OpenSSL
* TLS 1.2
* TLS 1.3
* X.509 Certificates
* PKI

## Course Information

**Course:** CSE467 Computer Security
**Semester:** Spring 2026
**Institution:** UNIST
