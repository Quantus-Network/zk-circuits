use plonky2::{
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_data::VerifierCircuitTarget,
        proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
    },
};
use wormhole_circuit::circuit::{CircuitFragment, C, D, F};
use wormhole_verifier::WormholeVerifier;

use crate::NUM_PROOFS_TO_AGGREGATE;

pub struct WormholeProofAggregatorTargets {
    verifier_data: VerifierCircuitTarget,
    proofs: Vec<ProofWithPublicInputsTarget<D>>,
}

pub struct WormholeProofAggregatorInputs {
    proofs: Vec<ProofWithPublicInputs<F, C, D>>,
}

/// A circuit that aggregates proofs from the Wormhole circuit.
pub struct WormholeProofAggregator {
    inner_verifier: WormholeVerifier,
}

impl Default for WormholeProofAggregator {
    fn default() -> Self {
        let inner_verifier = WormholeVerifier::new();
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
        builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
    ) -> Self::Targets {
        let circuit_data = WormholeVerifier::new().circuit_data;
        let verifier_data =
            builder.add_virtual_verifier_data(circuit_data.common.fri_params.config.cap_height);

        // Setup targets for proofs.
        let mut proofs = Vec::with_capacity(NUM_PROOFS_TO_AGGREGATE);
        for _ in 0..NUM_PROOFS_TO_AGGREGATE {
            proofs.push(builder.add_virtual_proof_with_pis(&circuit_data.common));
        }

        // Verify each aggregated proof separately.
        for proof in proofs.iter().take(NUM_PROOFS_TO_AGGREGATE) {
            builder.verify_proof::<C>(proof, &verifier_data, &circuit_data.common);
        }

        WormholeProofAggregatorTargets {
            verifier_data,
            proofs,
        }
    }

    fn fill_targets(
        &self,
        pw: &mut PartialWitness<F>,
        targets: Self::Targets,
        inputs: Self::PrivateInputs,
    ) -> anyhow::Result<()> {
        for (proof_target, proof) in targets.proofs.iter().zip(inputs.proofs.iter()) {
            pw.set_proof_with_pis_target(proof_target, proof)?;
        }

        pw.set_verifier_data_target(
            &targets.verifier_data,
            &self.inner_verifier.circuit_data.verifier_only,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use wormhole_circuit::circuit::tests::{build_and_prove_test, setup_test_builder_and_witness};
    use wormhole_circuit::inputs::CircuitInputs;
    use wormhole_prover::WormholeProver;

    fn run_test(
        inputs: WormholeProofAggregatorInputs,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let (mut builder, mut pw) = setup_test_builder_and_witness();
        let targets = WormholeProofAggregator::circuit(&mut builder);

        let aggregator = WormholeProofAggregator::new();
        aggregator.fill_targets(&mut pw, targets, inputs).unwrap();
        build_and_prove_test(builder, pw)
    }

    #[ignore = "takes too long"]
    #[test]
    #[cfg(feature = "testing")]
    fn build_and_verify_proof() {
        // Create proofs.
        let mut proofs = Vec::with_capacity(NUM_PROOFS_TO_AGGREGATE);
        for _ in 0..NUM_PROOFS_TO_AGGREGATE {
            let prover = WormholeProver::new();
            let inputs = CircuitInputs::default();
            let proof = prover.commit(&inputs).unwrap().prove().unwrap();
            proofs.push(proof);
        }

        let inputs = WormholeProofAggregatorInputs { proofs };
        run_test(inputs).unwrap();
    }
}
