# ZKP-Vote -- Private Voting Without MPC

## Overview

A single-round, privacy-preserving voting mechanism for blockchain validators that allows anonymous voting while preventing double voting.

## Design Goals

- Full voter anonymity (impossible to determine which address cast which vote)
- One vote per qualifying address (e.g. holding > 1B tokens)
- Prevention of double voting
- No coordination required between voters
- One round needed to complete election

It is not a goal to conceal partial results until the final tally.

## Protocol Details

### Eligibility

Any address holding more than 1B tokens gets exactly one vote. Holders of multiple billions are incentivized to split their holdings into separate 1B+ addresses to maximize voting power.

A merkle tree of all eligible addresses (those with >1B tokens) is created via snapshot at a given block height. The merkle root is published on chain. Optionally a smart contract can check the eligibility of the addresses and construct the merkle proof themselves.

### Vote Submission

Each vote consists of:
- A yes/no decision
- A nullifier
- A zero-knowledge proof of validity

The vote is broadcast as a transaction to any RPC node from any address. A smart contract maintains a tally and checks each proof.

### ZK Circuit

#### Public Inputs:
- Proposal ID
- Merkle root of eligible addresses
- Vote (yes/no)
- Nullifier = hash(hash(private_key) || proposal ID)

#### Private Inputs:
- Address private key
- Merkle proof of address inclusion in eligible set

The circuit checks eligibility and nullifier validity:
1.  Verify merkle proof
2.  Derive public_key from private_key and compare with public_key in merkle proof
3.  Compute hash(hash(private_key) || proposal_id) and compare with provided nullifier

### The smart contract
- Keeps public tally of votes
- Checks zkproof
- Records nullifier and checks for duplicates

## Security Properties

### 1. Privacy
- All votes look identical
- Cannot determine if multiple votes came from addresses owned by same entity

### 2. Auditable
- Vote is simple to tally, anyone can count the yes and no votes on chain
- Nullifiers are public, anyone can check for absence of double spend
- Eligibility criteria is publicly known and verified on chain

### 3. Correctness
- Only eligible addresses (>1B tokens) can vote
- Double voting prevented by deterministic nullifiers

## Trade-offs
- Slight loss of proportional representation compared to stake-weighted voting
- Some overhead from managing multiple addresses for large holders

## Testing

To run the tests for this circuit, use the following command:

```bash
cargo test -p vote-circuit
``` 