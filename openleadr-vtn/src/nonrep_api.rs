/// Non-repudiation REST endpoints for openleadr-rs.
///
/// GET  /nonrep/public-key
/// GET  /nonrep/sessions/{venID}/evidence
/// POST /nonrep/sessions/{venID}/verify
use std::sync::Arc;

use axum::{
    extract::{Path, State},
    Json,
};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{
    error::AppError,
    jwt::{Scope, User},
    nonrep_manager::NonRepManager,
};

// ---------------------------------------------------------------------------
// GET /nonrep/public-key
// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyResponse {
    pub public_key: String,
    pub algorithm:  String,
    pub encoding:   String,
}

pub async fn get_public_key(
    State(nonrep): State<Arc<NonRepManager>>,
) -> Result<Json<PublicKeyResponse>, AppError> {
    Ok(Json(PublicKeyResponse {
        public_key: nonrep.public_key_b64(),
        algorithm:  nonrep.algorithm().to_string(),
        encoding:   "base64".to_string(),
    }))
}

// ---------------------------------------------------------------------------
// GET /nonrep/sessions/{venID}/evidence
// ---------------------------------------------------------------------------

pub async fn get_evidence(
    State(nonrep): State<Arc<NonRepManager>>,
    Path(ven_id): Path<String>,
    User(user): User,
) -> Result<Json<serde_json::Value>, AppError> {
    if !user.scope.contains(Scope::ReadAll)
        && !user.scope.contains(Scope::ReadVenObjects)
        && !user.scope.contains(Scope::ReadTargets)
    {
        return Err(AppError::Forbidden("Missing required scope"));
    }

    if !nonrep.has_session(&ven_id) {
        return Err(AppError::NotFound);
    }

    let response = nonrep
        .finalize_session(&ven_id)
        .map_err(|_| AppError::NotFound)?;

    info!(ven_id, "nonrep: evidence returned");

    Ok(Json(serde_json::to_value(response)
        .map_err(AppError::SerdeJsonInternalServerError)?))
}

// ---------------------------------------------------------------------------
// POST /nonrep/sessions/{venID}/verify
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ProofBody {
    pub evidence: serde_json::Value,
    pub records:  serde_json::Value,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyResponse {
    pub ven_id: String,
    pub valid:  bool,
}

pub async fn verify_proof(
    Path(ven_id): Path<String>,
    User(_user): User,
    Json(body): Json<ProofBody>,
) -> Result<Json<VerifyResponse>, AppError> {
    use nonrep::{
        session::{Evidence, Proof, ProofRecord},
        Verifier,
    };
    #[cfg(not(feature = "pqc"))]
    use nonrep::signing::MockSigner;
    #[cfg(feature = "pqc")]
    use nonrep::signing::MlDsa44Signer;

    // Deserialise evidence
    let ev: Evidence = serde_json::from_value(body.evidence)
        .map_err(AppError::SerdeJsonBadRequest)?;

    // Identity binding — proof must belong to the authenticated VEN
    if !ev.ven_id.is_empty() && ev.ven_id != ven_id {
        return Err(AppError::Forbidden("Proof ven_id does not match path"));
    }

    // Deserialise proof records
    let records: Vec<ProofRecord> = serde_json::from_value(body.records)
        .map_err(AppError::SerdeJsonBadRequest)?;

    let proof = Proof { evidence: ev, records };

    #[cfg(not(feature = "pqc"))]
    let valid = Verifier::verify(&proof, &MockSigner::new(), None);
    #[cfg(feature = "pqc")]
    let valid = Verifier::verify(&proof, &MlDsa44Signer, None);
    info!(ven_id, valid, "nonrep: proof verified");

    Ok(Json(VerifyResponse { ven_id, valid }))
}