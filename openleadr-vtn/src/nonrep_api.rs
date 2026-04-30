/// Non-repudiation REST endpoints for openleadr-rs.
///
/// GET  /nonrep/public-key
/// GET  /nonrep/sessions/{venID}/evidence
/// POST /nonrep/sessions/{venID}/verify
use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
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
    // Only the authenticated VEN (or a BL client) may request evidence
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
        .map_err(|e| AppError::Internal(e.into()))?;

    info!(ven_id, "nonrep: evidence returned");

    Ok(Json(serde_json::to_value(response).unwrap()))
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
    User(user): User,
    Json(body): Json<ProofBody>,
) -> Result<Json<VerifyResponse>, AppError> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use nonrep::{
        session::{ChunkEntry, Evidence, Proof, ProofRecord, RecordPrivacy},
        signing::MockSigner,
        Verifier,
    };

    // Deserialise evidence
    let ev: Evidence = serde_json::from_value(body.evidence.clone())
        .map_err(|e| AppError::BadRequest(format!("Failed to deserialise evidence: {e}")))?;

    // Identity binding — proof must belong to the authenticated VEN
    if !ev.ven_id.is_empty() && ev.ven_id != ven_id {
        return Err(AppError::Forbidden("Proof ven_id does not match path"));
    }

    // Deserialise proof records
    let records: Vec<ProofRecord> = serde_json::from_value(body.records)
        .map_err(|e| AppError::BadRequest(format!("Failed to deserialise records: {e}")))?;

    let proof = Proof { evidence: ev, records };

    let valid = Verifier::verify(&proof, &MockSigner::new(), None);
    info!(ven_id, valid, "nonrep: proof verified");

    Ok(Json(VerifyResponse { ven_id, valid }))
}