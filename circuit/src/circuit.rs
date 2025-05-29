//! Wormhole Circuit.
//!
//! This module defines the zero-knowledge circuit for the Wormhole protocol.
use crate::nullifier::{Nullifier, NullifierTargets};
use crate::storage_proof::{StorageProof, StorageProofTargets};
use crate::substrate_account::{ExitAccountTargets, SubstrateAccount};
use crate::unspendable_account::{UnspendableAccount, UnspendableAccountTargets};
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    iop::witness::PartialWitness,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, ProverCircuitData, VerifierCircuitData},
        config::PoseidonGoldilocksConfig,
    },
};

// Plonky2 setup parameters.
pub const D: usize = 2; // D=2 provides 100-bits of security
pub type C = PoseidonGoldilocksConfig;
pub type F = GoldilocksField;

pub trait CircuitFragment {
    /// The targets that the circuit operates on. These are constrained in the circuit definition
    /// and filled with [`Self::fill_targets`].
    type Targets;

    /// Builds a circuit with the operating wires being provided by `Self::Targets`.
    fn circuit(targets: &Self::Targets, builder: &mut CircuitBuilder<F, D>);

    /// Fills the targets in the partial witness with the provided inputs.
    fn fill_targets(
        &self,
        pw: &mut PartialWitness<F>,
        targets: Self::Targets,
    ) -> anyhow::Result<()>;
}

#[derive(Debug, Clone)]
pub struct CircuitTargets {
    pub nullifier: NullifierTargets,
    pub unspendable_account: UnspendableAccountTargets,
    pub storage_proof: StorageProofTargets,
    pub exit_account: ExitAccountTargets,
}

impl CircuitTargets {
    pub fn new(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self {
            nullifier: NullifierTargets::new(builder),
            unspendable_account: UnspendableAccountTargets::new(builder),
            storage_proof: StorageProofTargets::new(builder),
            exit_account: ExitAccountTargets::new(builder),
        }
    }
}

pub struct WormholeCircuit {
    builder: CircuitBuilder<F, D>,
    targets: CircuitTargets,
}

impl Default for WormholeCircuit {
    fn default() -> Self {
        let config = CircuitConfig::standard_recursion_zk_config();
        Self::new(config)
    }
}

impl WormholeCircuit {
    pub fn new(config: CircuitConfig) -> Self {
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // Setup targets
        let targets = CircuitTargets::new(&mut builder);

        // Setup circuits.
        Nullifier::circuit(&targets.nullifier, &mut builder);
        UnspendableAccount::circuit(&targets.unspendable_account, &mut builder);
        StorageProof::circuit(&targets.storage_proof, &mut builder);
        SubstrateAccount::circuit(&targets.exit_account, &mut builder);

        Self { builder, targets }
    }

    pub fn targets(&self) -> CircuitTargets {
        self.targets.clone()
    }

    pub fn build_circuit(self) -> CircuitData<F, C, D> {
        self.builder.build()
    }

    pub fn build_prover(self) -> ProverCircuitData<F, C, D> {
        self.builder.build_prover()
    }

    pub fn build_verifier(self) -> VerifierCircuitData<F, C, D> {
        self.builder.build_verifier()
    }
}
