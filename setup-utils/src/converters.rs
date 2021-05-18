use crate::{BatchExpMode, SubgroupCheckMode};

#[derive(Clone, PartialEq, Eq, Debug, Copy)]
pub enum ContributionMode {
    Full,
    Chunked,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProvingSystem {
    Groth16,
    Marlin,
}

#[derive(Debug, Clone)]
pub enum CurveKind {
    Bls12_377,
    BW6,
}

pub fn curve_from_str(src: &str) -> Result<CurveKind, String> {
    let curve = match src.to_lowercase().as_str() {
        "bls12_377" => CurveKind::Bls12_377,
        "bw6" => CurveKind::BW6,
        _ => return Err("unsupported curve".to_string()),
    };
    Ok(curve)
}

pub fn contribution_mode_from_str(src: &str) -> Result<ContributionMode, String> {
    let mode = match src.to_lowercase().as_str() {
        "full" => ContributionMode::Full,
        "chunked" => ContributionMode::Chunked,
        _ => return Err("unsupported contribution mode. Currently supported: full, chunked".to_string()),
    };
    Ok(mode)
}

pub fn proving_system_from_str(src: &str) -> Result<ProvingSystem, String> {
    let system = match src.to_lowercase().as_str() {
        "groth16" => ProvingSystem::Groth16,
        "marlin" => ProvingSystem::Marlin,
        _ => return Err("unsupported proving system. Currently supported: groth16, marlin".to_string()),
    };
    Ok(system)
}

pub fn batch_exp_mode_from_str(src: &str) -> Result<BatchExpMode, String> {
    let batch_exp_mode = match src.to_lowercase().as_str() {
        "auto" => BatchExpMode::Auto,
        "direct" => BatchExpMode::Direct,
        "batch-inversion" => BatchExpMode::BatchInversion,
        _ => {
            return Err(
                "unsupported batch exponentiation mode. Currently supported: auto, direct, batch-inversion".to_string(),
            );
        }
    };
    Ok(batch_exp_mode)
}

pub fn subgroup_check_mode_from_str(src: &str) -> Result<SubgroupCheckMode, String> {
    let subgroup_check_mode = match src.to_lowercase().as_str() {
        "auto" => SubgroupCheckMode::Auto,
        "direct" => SubgroupCheckMode::Direct,
        "batched" => SubgroupCheckMode::Batched,
        _ => {
            return Err("unsupported subgroup check mode. Currently supported: auto, direct, batched".to_string());
        }
    };
    Ok(subgroup_check_mode)
}
