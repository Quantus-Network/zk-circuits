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
//! ```no_run
//! use wormhole_circuit::inputs::{CircuitInputs, PrivateCircuitInputs, PublicCircuitInputs};
//! use wormhole_circuit::nullifier::Nullifier;
//! use wormhole_circuit::storage_proof::ProcessedStorageProof;
//! use wormhole_circuit::substrate_account::SubstrateAccount;
//! use wormhole_circuit::unspendable_account::UnspendableAccount;
//! use wormhole_prover::WormholeProver;
//! use plonky2::plonk::circuit_data::CircuitConfig;
//!
//! # fn main() -> anyhow::Result<()> {
//! // Create inputs. In practice, each input would be gathered from the real node.
//! let inputs = CircuitInputs {
//!     private: PrivateCircuitInputs {
//!         secret: vec![1u8; 32],
//!         funding_nonce: 0,
//!         funding_account: [2u8; 32].into(),
//!         storage_proof: ProcessedStorageProof::new(vec![], vec![]).unwrap(),
//!         unspendable_account: [1u8; 32].into(),
//!     },
//!     public: PublicCircuitInputs {
//!         funding_amount: 1000,
//!         nullifier: [1u8; 32].into(),
//!         root_hash: [0u8; 32].into(),
//!         exit_account: [2u8; 32].into(),
//!     },
//! };
//!
//! let config = CircuitConfig::standard_recursion_config();
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

use wormhole_circuit::{
    circuit::CircuitTargets, inputs::CircuitInputs, substrate_account::SubstrateAccount,
};
use wormhole_circuit::{circuit::WormholeCircuit, nullifier::Nullifier};
use wormhole_circuit::{storage_proof::StorageProof, unspendable_account::UnspendableAccount};
use zk_circuits_common::circuit::{CircuitFragment, C, D, F};

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
        let storage_proof = StorageProof::try_from(circuit_inputs)?;
        let unspendable_account = UnspendableAccount::from(circuit_inputs);
        let exit_account = SubstrateAccount::try_from(circuit_inputs)?;

        nullifier.fill_targets(&mut self.partial_witness, targets.nullifier)?;
        unspendable_account.fill_targets(&mut self.partial_witness, targets.unspendable_account)?;
        storage_proof.fill_targets(&mut self.partial_witness, targets.storage_proof)?;
        exit_account.fill_targets(&mut self.partial_witness, targets.exit_account)?;

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
