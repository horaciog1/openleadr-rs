/// Non-repudiation session manager for the openleadr-rs VTN.
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

#[cfg(not(feature = "pqc"))]
use nonrep::signing::MockSigner;
#[cfg(feature = "pqc")]
use nonrep::signing::MlDsa44Signer;
use nonrep::{
    session::EvidenceGenerator,
    signing::Signer,
};
use rand::Rng;
use serde::Serialize;
use tracing::{debug, info, warn};

#[cfg(not(feature = "pqc"))]
type ActiveSigner = MockSigner;
#[cfg(feature = "pqc")]
type ActiveSigner = MlDsa44Signer;

// ---------------------------------------------------------------------------
// VTN key pair — generated once at startup, shared across all sessions
// ---------------------------------------------------------------------------

fn init_keypair() -> (Vec<u8>, Vec<u8>, &'static str) {
    #[cfg(not(feature = "pqc"))]
    let signer = ActiveSigner::new();
    #[cfg(feature = "pqc")]
    let signer = ActiveSigner;

    let kp = signer.generate_keypair();

    #[cfg(not(feature = "pqc"))]
    warn!("nonrep: using SHA3-512 mock signer — compile nonrep with feature 'pqc' for ML-DSA-44");
    #[cfg(feature = "pqc")]
    info!("nonrep: using ML-DSA-44 (NIST FIPS 204) post-quantum signer");

    (kp.public_key, kp.secret_key, signer.algorithm_name())
}

// ---------------------------------------------------------------------------
// Per-VEN session state
// ---------------------------------------------------------------------------

struct Session {
    generator:    EvidenceGenerator<ActiveSigner>,
    session_key:  Vec<u8>,
    nonces:       Vec<Vec<u8>>,
    payloads:     Vec<Vec<u8>>,
    record_count: usize,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("record_count", &self.record_count)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Public session manager
// ---------------------------------------------------------------------------

/// HTTP response body for `GET /nonrep/sessions/{venID}/evidence`
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceResponse {
    pub ven_id:      String,
    pub session_key: String,
    pub evidence:    serde_json::Value,
    pub nonces:      Vec<String>,
    pub payloads:    Vec<String>,
}

#[derive(Debug)]
pub struct NonRepManager {
    sessions:   Mutex<HashMap<String, Session>>,
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
    alg_name:   &'static str,
}

impl NonRepManager {
    pub fn new() -> Arc<Self> {
        let (pk, sk, alg) = init_keypair();
        Arc::new(Self {
            sessions:   Mutex::new(HashMap::new()),
            public_key: pk,
            secret_key: sk,
            alg_name:   alg,
        })
    }

    pub fn public_key_b64(&self) -> String {
        use base64::{engine::general_purpose::STANDARD, Engine};
        STANDARD.encode(&self.public_key)
    }

    pub fn algorithm(&self) -> &'static str {
        self.alg_name
    }

    pub fn has_session(&self, ven_id: &str) -> bool {
        self.sessions.lock().unwrap().contains_key(ven_id)
    }

    pub fn record_message(&self, ven_id: &str, payload: &[u8], is_generator: bool) {
        let mut sessions = self.sessions.lock().unwrap();

        if !sessions.contains_key(ven_id) {
            let mut session_key = vec![0u8; 32];
            rand::rng().fill_bytes(&mut session_key);

            #[cfg(not(feature = "pqc"))]
            let active_signer = ActiveSigner::new();
            #[cfg(feature = "pqc")]
            let active_signer = ActiveSigner;

            let gen = EvidenceGenerator::new(
                session_key.clone(),
                self.public_key.clone(),
                self.secret_key.clone(),
                16,
                32,
                active_signer,
            );

            sessions.insert(ven_id.to_string(), Session {
                generator:    gen,
                session_key,
                nonces:       Vec::new(),
                payloads:     Vec::new(),
                record_count: 0,
            });

            info!(ven_id, "nonrep: session started");
        }

        let session = sessions.get_mut(ven_id).unwrap();
        let mut nonce = vec![0u8; 16];
        rand::rng().fill_bytes(&mut nonce);

        session.generator.add_record(payload, &nonce, is_generator);
        session.nonces.push(nonce);
        session.payloads.push(payload.to_vec());
        session.record_count += 1;

        let direction = if is_generator { "VTN→VEN" } else { "VEN→VTN" };
        debug!(ven_id, record = session.record_count, direction, bytes = payload.len(), "nonrep: recorded");
    }

    pub fn finalize_session(&self, ven_id: &str) -> Result<EvidenceResponse, String> {
        use base64::{engine::general_purpose::STANDARD, Engine};

        let mut sessions = self.sessions.lock().unwrap();
        let session = sessions
            .remove(ven_id)
            .ok_or_else(|| format!("no active non-rep session for ven_id={ven_id}"))?;

        let evidence = session
            .generator
            .finalize(None, None, ven_id)
            .map_err(|e| e.to_string())?;

        info!(ven_id, records = session.record_count, "nonrep: session finalised");

        let ev_json = serde_json::to_value(&evidence).map_err(|e| e.to_string())?;

        Ok(EvidenceResponse {
            ven_id:      ven_id.to_string(),
            session_key: STANDARD.encode(&session.session_key),
            evidence:    ev_json,
            nonces:      session.nonces.iter().map(|n| STANDARD.encode(n)).collect(),
            payloads:    session.payloads.iter().map(|p| STANDARD.encode(p)).collect(),
        })
    }
}