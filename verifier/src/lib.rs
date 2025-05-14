/// A verifier for the wormhole circuit.
///
///# Example
///
/// Create a verifier and verify a proof:
///
///```
/// use wormhole_circuit::inputs::CircuitInputs;
/// use wormhole_prover::WormholeProver;
/// use wormhole_verifier::WormholeVerifier;
/// #
/// # fn main() -> anyhow::Result<()> {
/// # let inputs = CircuitInputs::default();
/// # let prover = WormholeProver::new();
/// # let proof = prover.commit(&inputs)?.prove()?;
///
/// let verifier = WormholeVerifier::new();
/// verifier.verify(proof)?;
/// # Ok(())
/// # }
/// ```
use plonky2::plonk::{circuit_data::VerifierCircuitData, proof::ProofWithPublicInputs};

use wormhole_circuit::circuit::{WormholeCircuit, C, D, F};

pub struct WormholeVerifier {
    circuit_data: VerifierCircuitData<F, C, D>,
}

impl Default for WormholeVerifier {
    fn default() -> Self {
        let wormhole_circuit = WormholeCircuit::new();
        let circuit_data = wormhole_circuit.build_verifier();

        Self { circuit_data }
    }
}

impl WormholeVerifier {
    /// Creates a new [`WormholeVerifier`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Verify a [`ProofWithPublicInputs`] generated from a [`crate::prover::WormholeProver`].
    ///
    /// # Errors
    ///
    /// Returns an error if the proof is not valid.
    pub fn verify(&self, proof: ProofWithPublicInputs<F, C, D>) -> anyhow::Result<()> {
        self.circuit_data.verify(proof)
    }
}

#[cfg(test)]
mod tests {
    use super::WormholeVerifier;
    use wormhole_circuit::inputs::CircuitInputs;
    use wormhole_prover::WormholeProver;

    #[test]
    fn verify_simple_proof() {
        let prover = WormholeProver::new();
        let inputs = CircuitInputs::default();
        let proof = prover.commit(&inputs).unwrap().prove().unwrap();

        let verifier = WormholeVerifier::new();
        verifier.verify(proof).unwrap();
    }
}
