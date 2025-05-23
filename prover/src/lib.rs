//! Prover logic for the Wormhole circuit.
//!
//! This module provides the [`WormholeProver`] type, which allows committing inputs to the circuit
//! and generating a zero-knowledge proof using those inputs.
//!
//! The typical usage flow involves:
//! 1. Initializing the prover (e.g., via [`WormholeProver::default`] or [`WormholeProver::new`]).
//! 2. Creating user inputs with [`CircuitInputs`].
//! 3. Committing user inputs using [`WormholeProver::commit`].
//! 4. Generating a proof using [`WormholeProver::prove`].
//!
//! # Example
//!
//! ```
//! use wormhole_circuit::inputs::CircuitInputs;
//! use wormhole_prover::WormholeProver;
//! use plonky2::plonk::circuit_data::CircuitConfig;
//!
//! # fn main() -> anyhow::Result<()> {
//! # let inputs = CircuitInputs::test_inputs();
//! let config = CircuitConfig::standard_recursion_zk_config();
//! let prover = WormholeProver::new(config);
//! let proof = prover.commit(&inputs)?.prove()?;
//! # Ok(())
//! # }
//! ```
use anyhow::bail;
use plonky2::{
    iop::witness::PartialWitness,
    plonk::{
        circuit_data::{CircuitConfig, ProverCircuitData},
        proof::ProofWithPublicInputs,
    },
};

use wormhole_circuit::circuit::{WormholeCircuit, C, D, F};
use wormhole_circuit::codec::ByteCodec;
use wormhole_circuit::{
    circuit::{CircuitFragment, CircuitTargets},
    inputs::CircuitInputs,
    nullifier::{Nullifier, NullifierInputs},
    storage_proof::StorageProof,
    substrate_account::SubstrateAccount,
    unspendable_account::{UnspendableAccount, UnspendableAccountInputs},
};

#[derive(Debug)]
pub struct WormholeProver {
    pub circuit_data: ProverCircuitData<F, C, D>,
    partial_witness: PartialWitness<F>,
    targets: Option<CircuitTargets>,
}

impl Default for WormholeProver {
    fn default() -> Self {
        let wormhole_circuit = WormholeCircuit::default();
        let partial_witness = PartialWitness::new();

        let targets = Some(wormhole_circuit.targets());
        let circuit_data = wormhole_circuit.build_prover();

        Self {
            circuit_data,
            partial_witness,
            targets,
        }
    }
}

impl WormholeProver {
    /// Creates a new [`WormholeProver`].
    pub fn new(config: CircuitConfig) -> Self {
        let wormhole_circuit = WormholeCircuit::new(config);
        let partial_witness = PartialWitness::new();

        let targets = Some(wormhole_circuit.targets());
        let circuit_data = wormhole_circuit.build_prover();

        Self {
            circuit_data,
            partial_witness,
            targets,
        }
    }

    /// Commits the provided [`CircuitInputs`] to the circuit by filling relevant targets.
    ///
    /// # Errors
    ///
    /// Returns an error if the prover has already commited to inputs previously.
    pub fn commit(mut self, circuit_inputs: &CircuitInputs) -> anyhow::Result<Self> {
        let Some(targets) = self.targets.take() else {
            bail!("prover has already commited to inputs");
        };
        let nullifier = Nullifier::from(circuit_inputs);
        let unspendable_account = UnspendableAccount::from(circuit_inputs);
        let storage_proof = StorageProof::from(circuit_inputs);
        let exit_account = SubstrateAccount::from(circuit_inputs);

        let nullifier_inputs = NullifierInputs::new(
            &circuit_inputs.private.secret,
            circuit_inputs.private.funding_nonce,
            &circuit_inputs.private.funding_account.to_bytes(),
        );
        let unspendable_account_inputs =
            UnspendableAccountInputs::new(&circuit_inputs.private.secret);

        nullifier.fill_targets(
            &mut self.partial_witness,
            targets.nullifier,
            nullifier_inputs,
        )?;
        unspendable_account.fill_targets(
            &mut self.partial_witness,
            targets.unspendable_account,
            unspendable_account_inputs,
        )?;

        storage_proof.fill_targets(&mut self.partial_witness, targets.storage_proof, ())?;
        exit_account.fill_targets(&mut self.partial_witness, targets.exit_account, ())?;

        Ok(self)
    }

    /// Prove the circuit with commited values. It's necessary to call [`WormholeProver::commit`]
    /// before running this function.
    ///
    /// # Errors
    ///
    /// Returns an error if the prover has not commited to any inputs.
    pub fn prove(self) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        if self.targets.is_some() {
            bail!("prover has not commited to any inputs")
        }
        self.circuit_data.prove(self.partial_witness)
    }
}

#[cfg(test)]
mod tests {
    use super::WormholeProver;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use wormhole_circuit::inputs::CircuitInputs;

    const CIRCUIT_CONFIG: CircuitConfig = CircuitConfig::standard_recursion_config();

    #[test]
    fn commit_and_prove() {
        let prover = WormholeProver::new(CIRCUIT_CONFIG);
        let inputs = CircuitInputs::test_inputs();
        prover.commit(&inputs).unwrap().prove().unwrap();
    }

    #[test]
    #[ignore = "debug"]
    fn get_public_inputs() {
        let prover = WormholeProver::new(CIRCUIT_CONFIG);
        let inputs = CircuitInputs::test_inputs();
        let proof = prover.commit(&inputs).unwrap().prove().unwrap();
        let public_inputs = proof.public_inputs;
        println!("{:?}", public_inputs);
    }

    #[test]
    fn proof_can_be_deserialized() {
        use wormhole_circuit::inputs::PublicCircuitInputs;

        let prover = WormholeProver::new(CIRCUIT_CONFIG);
        let inputs = CircuitInputs::test_inputs();
        let proof = prover.commit(&inputs).unwrap().prove().unwrap();
        let public_inputs = PublicCircuitInputs::try_from(proof).unwrap();
        println!("{:?}", public_inputs);
    }
}
