use anyhow::bail;
use plonky2::plonk::circuit_data::CommonCircuitData;
use wormhole_verifier::ProofWithPublicInputs;
use zk_circuits_common::circuit::{C, D, F};

pub fn pad_with_dummy_proofs(
    mut proofs: Vec<ProofWithPublicInputs<F, C, D>>,
    proof_len: usize,
    _common_data: &CommonCircuitData<F, D>,
) -> anyhow::Result<Vec<ProofWithPublicInputs<F, C, D>>> {
    let num_proofs = proofs.len();

    if num_proofs > proof_len {
        bail!("proofs to aggregate was more than the maximum allowed")
    }

    if num_proofs == proof_len {
        return Ok(proofs);
    }

    if num_proofs == 0 {
        bail!("cannot pad an empty list of proofs");
    }

    let dummy_proof = proofs.last().unwrap().clone();
    for _ in 0..(proof_len - num_proofs) {
        proofs.push(dummy_proof.clone());
    }

    Ok(proofs)
}
