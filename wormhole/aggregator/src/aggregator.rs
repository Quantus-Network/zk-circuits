use anyhow::bail;
use plonky2::plonk::circuit_data::{CircuitConfig, VerifierCircuitData};
use wormhole_verifier::{ProofWithPublicInputs, WormholeVerifier};
use zk_circuits_common::circuit::{C, D, F};

use crate::{
    circuits::tree::{aggregate_to_tree, AggregatedProof, TreeAggregationConfig},
    util::pad_with_dummy_proofs,
};

/// A circuit that aggregates proofs from the Wormhole circuit.
pub struct WormholeProofAggregator {
    pub leaf_circuit_data: VerifierCircuitData<F, C, D>,
    pub config: TreeAggregationConfig,
    pub proofs_buffer: Option<Vec<ProofWithPublicInputs<F, C, D>>>,
}

impl Default for WormholeProofAggregator {
    fn default() -> Self {
        let circuit_config = CircuitConfig::standard_recursion_zk_config();
        Self::from_circuit_config(circuit_config)
    }
}

impl WormholeProofAggregator {
    /// Creates a new [`WormholeProofAggregator`] with a given [`VerifierCircuitData`].
    pub fn new(verifier_circuit_data: VerifierCircuitData<F, C, D>) -> Self {
        let aggregation_config = TreeAggregationConfig::default();
        let proofs_buffer = Some(Vec::with_capacity(aggregation_config.num_leaf_proofs));

        Self {
            leaf_circuit_data: verifier_circuit_data,
            config: aggregation_config,
            proofs_buffer,
        }
    }

    /// Creates a new [`WormholeProofAggregator`] with a given [`CircuitConfig`]
    /// by compiling the circuit data from a [`WormholeVerifier`].
    pub fn from_circuit_config(circuit_config: CircuitConfig) -> Self {
        let leaf_circuit_data = WormholeVerifier::new(circuit_config.clone(), None).circuit_data;
        let aggregation_config = TreeAggregationConfig::default();
        let proofs_buffer = Some(Vec::with_capacity(aggregation_config.num_leaf_proofs));

        Self {
            leaf_circuit_data,
            config: aggregation_config,
            proofs_buffer,
        }
    }

    pub fn with_config(mut self, config: TreeAggregationConfig) -> Self {
        self.config = config;
        self
    }

    pub fn push_proof(&mut self, proof: ProofWithPublicInputs<F, C, D>) -> anyhow::Result<()> {
        if let Some(proofs_buffer) = self.proofs_buffer.as_mut() {
            if proofs_buffer.len() >= self.config.num_leaf_proofs {
                bail!("tried to add proof when proof buffer is full")
            }
            proofs_buffer.push(proof);
        } else {
            self.proofs_buffer = Some(vec![proof]);
        }

        Ok(())
    }

    /// Aggregates `N` number of leaf proofs into an [`AggregatedProof`].
    pub fn aggregate(&mut self) -> anyhow::Result<AggregatedProof<F, C, D>> {
        let Some(proofs) = self.proofs_buffer.take() else {
            bail!("there are no proofs to aggregate")
        };

        let padded_proofs = pad_with_dummy_proofs(
            proofs,
            self.config.num_leaf_proofs,
            &self.leaf_circuit_data.common,
        )?;
        let root_proof = aggregate_to_tree(
            padded_proofs,
            &self.leaf_circuit_data.common,
            &self.leaf_circuit_data.verifier_only,
            self.config,
        )?;

        Ok(root_proof)
    }
}
