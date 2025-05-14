use plonky2::plonk::proof::ProofWithPublicInputsTarget;
use plonky2::{iop::witness::PartialWitness, plonk::circuit_data::VerifierCircuitTarget};

use wormhole_circuit::circuit::{CircuitFragment, C, D, F};
use wormhole_verifier::WormholeVerifier;

// Constants for the recursion.
const NUM_PROOFS_TO_AGGREGATE: usize = 10;

pub struct WormholeProofAggregatorTargets {
    verifier_data: VerifierCircuitTarget,
    proofs: Vec<ProofWithPublicInputsTarget<D>>,
}

/// A circuit that aggregates proofs from the Wormhole circuit.
pub struct WormholeProofAggregator;

impl CircuitFragment for WormholeProofAggregator {
    type PrivateInputs = ();
    type Targets = WormholeProofAggregatorTargets;

    fn circuit(
        builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
    ) -> Self::Targets {
        let verifier = WormholeVerifier::new();
        let verifier_data = builder.add_virtual_verifier_data(NUM_PROOFS_TO_AGGREGATE);

        // Setup targets for proofs.
        let mut proofs = Vec::with_capacity(NUM_PROOFS_TO_AGGREGATE);
        for _ in 0..NUM_PROOFS_TO_AGGREGATE {
            proofs.push(builder.add_virtual_proof_with_pis(&verifier.circuit_data.common));
        }

        // Verify each aggregated proof separately.
        for proof in proofs.iter().take(NUM_PROOFS_TO_AGGREGATE) {
            builder.verify_proof::<C>(proof, &verifier_data, &verifier.circuit_data.common);
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
        todo!()
    }
}
