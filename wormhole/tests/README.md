# Wormhole Circuit Tests

This is the dedicated crate for all tests and benchmarks in the Wormhole Circuit project. Tests and benchmarks are organized by the crate they test, following a consistent structure.

## Running Tests

To run all tests:
```bash
cargo test
```

To run tests for a specific module:
```bash
# For prover tests
cargo test prover

# For circuit tests
cargo test circuit

# For verifier tests
cargo test verifier

# For aggregator tests
cargo test aggregator
```

## Running Benchmarks

To run all benchmarks:
```bash
cargo bench
```

To run specific benchmarks:
```bash
# For prover benchmarks
cargo bench -p tests --bench prover

# For verifier benchmarks
cargo bench -p tests --bench verifier
```

## Adding New Tests

When adding new tests:
1. Place them in the appropriate subdirectory under `src/` matching the crate name they test
2. For benchmarks, add them to the corresponding file in the `benches/` directory
3. Follow the existing test patterns and organization

## Note

This crate is specifically designed to contain all tests and benchmarks for the Wormhole Circuit project. All new tests should be added here rather than in the individual crates to maintain a centralized testing structure. 