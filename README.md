# ZK Circuits

This repository contains Zero-Knowledge circuits for the Quantus Network, implemented using Plonky2.

## Project Structure

This repository is a Cargo workspace organized to clearly separate different circuit implementations and their components.

-   `common/`: A crate containing shared code, utilities, and common circuit gadgets used by other circuits in the workspace.
-   `wormhole/`: This directory contains all crates related to the Wormhole bridge message verification circuit.
    -   `circuit/`: The core Plonky2 circuit definition for Wormhole message verification.
    -   `prover/`: The prover for the Wormhole circuit.
    -   `verifier/`: The verifier for the Wormhole circuit.
    -   `aggregator/`: A circuit for recursively aggregating Wormhole proofs.
    -   `tests/`: Integration tests for the complete Wormhole circuit.
-   `voting/`: A separate circuit implementation for a voting system.

## Prerequisites

You can set up your development environment manually or use the provided Nix flake for a reproducible setup.

### Manually

Ensure you have Rust installed. If not, you can install Rust using [rustup](https://rustup.rs/):

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### Nix flake

To use the Nix flake, first ensure that you have Nix installed. You can install Nix by running:

```sh
curl -L https://nixos.org/nix/install | sh -s -- --daemon
```

To enter a shell with all the dependencies pre-installed, run:

```sh
nix --experimental-features 'nix-command flakes' develop
```

## Setup

Clone the repository:

```sh
git clone https://github.com/Resonance-Network/zk-circuits
cd zk-circuits
```

## Building & Testing

To build all crates in the workspace:
```sh
cargo build
```

Run the entire test suite:
```sh
cargo test
```

You can also run tests for a specific package, for example, for the `wormhole-circuit`:
```sh
cargo test -p wormhole-circuit
```

## Benchmarks

To run prover and verifier benchmarks:

```sh
cargo bench
```
