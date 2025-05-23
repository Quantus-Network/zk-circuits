# Wormhole Circuit

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
git clone https://github.com/Resonance-Network/wormhole-prover
cd wormhole-prover
```

## Testing

Run the test suite:

```sh
cargo test
```

## Benchmarks

To run prover and verifier benchmarks:

```sh
cargo bench
```
