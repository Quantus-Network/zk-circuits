# Wormhole Circuit

## Overview

Provides a Zero-Knowledge circuit that can verify wormhole transactions.

### ZK Circuit Details

**Public Inputs:**

- `funding_amount`: The value or quantity of funds being transacted.
- `nullifier`: A unique, transaction-specific value derived from private information. Its purpose is to prevent double-spending by ensuring that a given set of private inputs can only be used to generate one valid proof.
- `root_hash`: The root hash of a Substrate Merkle Patricia storage proof trie.
- `exit_account`: The public address where the funding_amount is intended to be sent after the transaction is verified.

**Private Inputs:**

- `secret`: A confidential, randomly generated value unique to the prover, often serving as a primary secret for deriving other transaction components.
- `storage_proof`: A storage proof of a Merkle Patricia trie proving inclusion of the transaction event.
- `funding_nonce`: A unique, random number used in conjunction with the secret and funding_account to derive the nullifier.
- `funding_account`: The private key or identifier associated with the source of the funds, used to derive the nullifier and confirm ownership.
- `unspendable_account`: A private identifier derived from the secret that, when hashed, provides a verifiable unspendable (burn) address.

#### Logic Flow

**The circuit does the following**:

1. **Nullifier Derivation:**

- Computes `H(H(salt || secret || funding_nonce || funding_account))`.
- Compares the derived value against the provided `nullifier` public input.

2. **Unspendable Account Derivation:**

- Computes `H(H(salt || secret))`
- Compare the derived value with the provided `unspendable_account`.

3. **Storage Proof Verification:**

- The circuit verifies the `storage_proof` to confirm that a specific leaf (the transaction event) is part of the proof.
- To verify that the storage proof is valid, the circuit traverses the tree in root-to-leaf order, and for each node:
  1. Compares the expected hash against the hash of the current node (verifies inclusion).
  2. Updates the expected hash to be equal to the hash of the current node.
  3. If this node is the leaf node: additionally verify that it includes hash of the leaf inputs.

## Testing

To run the tests for this circuit, please follow the instructions in the [tests](./tests/) crate.

## Building the Circuit binary

The core circuit logic can be compiled into a binary artifact
(`circuit_data.bin`) that can be used by other parts of the system. This file
must be generated manually after cloning the repository or after making any
changes to the circuit logic.
To build the circuit binary, run the following command from the root of the workspace:

```sh
cargo run --release -p circuit-builder
```

This will create a `circuit_data.bin` file in the root of the workspace. You must re-run this command any time you make changes to the files in the `wormhole/circuit` crate to ensure the binary is up-to-date.
