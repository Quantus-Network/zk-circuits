use plonky2::{
    field::types::Field,
    iop::{
        target::Target,
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CommonCircuitData, VerifierCircuitTarget},
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use wormhole_circuit::{
    circuit::{CircuitFragment, C, D, F},
    gadgets::is_const_less_than,
};
use wormhole_verifier::WormholeVerifier;

use crate::MAX_NUM_PROOFS_TO_AGGREGATE;

#[derive(Debug, Clone)]
pub struct WormholeProofAggregatorTargets {
    verifier_data: VerifierCircuitTarget,
    proofs: [ProofWithPublicInputsTarget<D>; MAX_NUM_PROOFS_TO_AGGREGATE],
    num_proofs: Target,
    // HACK: This allows us to only create `circuit_data` once.
    circuit_data: CommonCircuitData<F, D>,
}

impl WormholeProofAggregatorTargets {
    pub fn new(builder: &mut CircuitBuilder<F, D>, config: CircuitConfig) -> Self {
        let circuit_data = WormholeVerifier::new(config, None).circuit_data.common;
        let verifier_data =
            builder.add_virtual_verifier_data(circuit_data.fri_params.config.cap_height);

        // Setup targets for proofs.
        let num_proofs = builder.add_virtual_target();
        let mut proofs = Vec::with_capacity(MAX_NUM_PROOFS_TO_AGGREGATE);
        for _ in 0..MAX_NUM_PROOFS_TO_AGGREGATE {
            proofs.push(builder.add_virtual_proof_with_pis(&circuit_data));
        }

        let proofs: [ProofWithPublicInputsTarget<D>; MAX_NUM_PROOFS_TO_AGGREGATE] =
            std::array::from_fn(|_| builder.add_virtual_proof_with_pis(&circuit_data));

        Self {
            verifier_data,
            proofs,
            num_proofs,
            circuit_data,
        }
    }
}

pub struct WormholeProofAggregatorInputs {
    pub proofs: Vec<ProofWithPublicInputs<F, C, D>>,
    pub num_proofs: usize,
}

impl WormholeProofAggregatorInputs {
    pub fn new(proofs: Vec<ProofWithPublicInputs<F, C, D>>, num_proofs: usize) -> Self {
        Self { proofs, num_proofs }
    }
}

/// A circuit that aggregates proofs from the Wormhole circuit.
pub struct WormholeProofAggregator {
    inner_verifier: WormholeVerifier,
}

impl Default for WormholeProofAggregator {
    fn default() -> Self {
        let inner_verifier = WormholeVerifier::default();
        Self { inner_verifier }
    }
}

impl WormholeProofAggregator {
    pub fn new() -> Self {
        Self::default()
    }
}

impl CircuitFragment for WormholeProofAggregator {
    type PrivateInputs = WormholeProofAggregatorInputs;
    type Targets = WormholeProofAggregatorTargets;

    fn circuit(
        &Self::Targets {
            ref verifier_data,
            ref proofs,
            num_proofs,
            ref circuit_data,
        }: &Self::Targets,
        builder: &mut CircuitBuilder<F, D>,
    ) {
        // Verify each aggregated proof separately.
        let n_log = (usize::BITS - (MAX_NUM_PROOFS_TO_AGGREGATE - 1).leading_zeros()) as usize;
        for (i, proof) in proofs.iter().enumerate() {
            let is_proof = is_const_less_than(builder, i, num_proofs, n_log);
            builder
                .conditionally_verify_proof_or_dummy::<C>(
                    is_proof,
                    proof,
                    verifier_data,
                    circuit_data,
                )
                .unwrap();
        }
    }

    fn fill_targets(
        &self,
        pw: &mut PartialWitness<F>,
        targets: Self::Targets,
        inputs: Self::PrivateInputs,
    ) -> anyhow::Result<()> {
        pw.set_target(
            targets.num_proofs,
            F::from_canonical_usize(inputs.num_proofs),
        )?;
        for (proof_target, proof) in targets.proofs.iter().zip(inputs.proofs.iter()) {
            pw.set_proof_with_pis_target(proof_target, proof)?;
        }

        pw.set_verifier_data_target(
            &targets.verifier_data,
            &self.inner_verifier.circuit_data.verifier_only,
        )
    }
}
