//! Verifier logic for the Wormhole circuit.
//!
//! This module contains the [`WormholeVerifier`] type, which can verify proofs generated
//! by the [`wormhole_prover::WormholeProver`].
//!
//! # Example
//!
//! ```
//! use wormhole_circuit::inputs::CircuitInputs;
//! use wormhole_prover::WormholeProver;
//! use wormhole_verifier::WormholeVerifier;
//!
//! # fn main() -> anyhow::Result<()> {
//! # let inputs = CircuitInputs::test_default();
//! # let prover = WormholeProver::new();
//! # let proof = prover.commit(&inputs)?.prove()?;
//!
//! let verifier = WormholeVerifier::new();
//! verifier.verify(proof)?;
//! # Ok(())
//! # }
//! ```
use plonky2::plonk::{
    circuit_data::VerifierCircuitData
};
pub use plonky2::plonk::proof::ProofWithPublicInputs;
use wormhole_circuit::{C, D, F, WormholeCircuit};
pub use wormhole_circuit::inputs::CircuitInputs;

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
/// # let inputs = CircuitInputs::test_default();
/// # let prover = WormholeProver::new();
/// # let proof = prover.commit(&inputs)?.prove()?;
///
/// let verifier = WormholeVerifier::new();
/// verifier.verify(proof)?;
/// # Ok(())
/// # }
/// ```
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

    /// Verify a [`ProofWithPublicInputs`] generated from a [`wormhole_prover::WormholeProver`].
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
    use wormhole_circuit::inputs::CircuitInputs;
    use wormhole_prover::WormholeProver;
    use super::WormholeVerifier;

    #[test]
    fn verify_simple_proof() {
        let prover = WormholeProver::new();
        let inputs = CircuitInputs::test_default();
        let proof = prover.commit(&inputs).unwrap().prove().unwrap();

        let verifier = WormholeVerifier::new();
        verifier.verify(proof).unwrap();
    }
}
