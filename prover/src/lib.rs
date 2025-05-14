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
//! use wormhole_prover::prover::WormholeProver;
//!
//! # fn main() -> anyhow::Result<()> {
//! # let inputs = CircuitInputs::default();
//! let prover = WormholeProver::new();
//! let proof = prover.commit(&inputs)?.prove()?;
//! # Ok(())
//! # }
//! ```

pub mod prover;