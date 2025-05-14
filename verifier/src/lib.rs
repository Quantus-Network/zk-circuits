/// A verifier for the wormhole circuit.
///
///# Example
///
/// Create a verifier and verify a proof:
///
///```
/// use wormhole_circuit::inputs::CircuitInputs;
/// use wormhole_prover::prover::WormholeProver;
/// use wormhole_verifier::verifier::WormholeVerifier;
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

pub mod verifier;