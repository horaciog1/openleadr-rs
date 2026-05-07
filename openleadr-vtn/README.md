![maintenance-status](https://img.shields.io/badge/maintenance-actively--developed-brightgreen.svg)
![codecov](https://codecov.io/gh/OpenLEADR/openleadr-rs/graph/badge.svg?token=BKQ0QW9G8H)
[![Checks](https://github.com/OpenLEADR/openleadr-rs/actions/workflows/checks.yml/badge.svg)](https://github.com/OpenLEADR/openleadr-rs/actions/workflows/checks.yml)
![Crates.io Version](https://img.shields.io/crates/v/openleadr-vtn)

# OpenADR 3.1 VTN server in Rust

![LF energy OpenLEADR logo](../openleadr-logo.svg)

This crate contains an OpenADR VTN implementation.

The following contains information specific to the VTN application, i.e., the server.
If you are interested in information about the whole project, please visit the [project level Readme](../README.md).

## Deviations from the specification
Version 3.1.0 of the OpenADR specification does not make a difference between a BL and VEN client with respect to the `write_vens` OAuth scope.
The OpenLEADR implementation deviates from the specification by splitting the `write_vens` scope into two scopes: `write_vens_ven` and `write_vens_bl`.
To be as compatible as possible with the specification, the `write_vens` scope is still supported as an alias for `write_vens_ven`.
For detailed information, see the issue on the specification if you have access ([oadr3-org/specification#396](https://github.com/oadr3-org/specification/issues/396)).

## Getting started
Your machine needs a recent version of Rust installed.
Please refer to the [official installation website](https://rustup.rs/) for the setup.
To apply the Database migrations, you also need the sqlx-cli installed.
Simply run `cargo install sqlx-cli`.

All the following commands are executed in the root directory of the Git repository.

### Database setup

First, start up a postgres database. For example, using docker compose:

```bash
docker compose up -d db
```

Run the [migrations](https://github.com/launchbadge/sqlx/blob/main/sqlx-cli/README.md):

```bash
cargo sqlx migrate run
```

### How to use

Running the VTN using cargo:

```bash
RUST_LOG=trace cargo run --bin openleadr-vtn
```

Running the VTN using docker-compose:

```bash
docker compose up -d
```

### Internal vs. external OAuth provider
The VTN implementation does feature an implementation of an OAuth provider including user management APIs
to allow for an easy setup.
The OpenADR specification does not require this feature but mentions that there must exist some OAuth provider somewhere.
Generally, the idea of OAuth is to decouple the authorization from the resource server, here the VTN.
Therefore, the OAuth provider feature is optional.
If you want to use it, you need to enable it during compile time. Otherwise you need to disable it during runtime.

**During runtime**
The OAuth configuration of the VTN is done via the following environment variables:
- `OAUTH_TYPE` (allowed values: `INTERNAL`, `EXTERNAL`. Defaults to `INTERNAL`)
- `OAUTH_BASE64_SECRET` (must be at least 256 bit long. Required if `OAUTH_KEY_TYPE` is `HMAC`)
- `OAUTH_KEY_TYPE`(allows values: `HMAC`, `RSA`, `EC`, `ED`. Defaults to `HMAC`)
- `OAUTH_PEM` (path to a PEM encoded public key file. Either `OAUTH_PEM` or `OAUTH_JWKS_LOCATION` is required for all `OAUTH_KEY_TYPE`s, except `HMAC`)
- `OAUTH_JWKS_LOCATION` (path to the OAUTH server well known JWKS endpoint.  Either `OAUTH_PEM` or `OAUTH_JWKS_LOCATION` is required for all `OAUTH_KEY_TYPE`s, except `HMAC`)
- `OAUTH_VALID_AUDIENCES` (specifies the list of valid audiences for token validation, ensuring that the token is intended for the correct recipient. If not set there must not be an `aud` claim.)
- `OAUTH_TOKEN_URL` (URL to the OAUTH server token endpoint. For example `https://localhost:3000/auth/token` when using the internal OAuth provider. Required)

The internal OAuth provider does only support `HMAC` keys.

**During compiletime**
If you need the internal OAuth feature, you can enable it during compilation with the feature flag `internal-oauth`.
Therefore, run
```bash
cargo build/run --bin openleadr-vtn --features=internal-oauth [--release]
```

### Testing
To run the tests, you need to start a postgres database and run the migrations:
```bash
docker compose up -d db
cargo sqlx migrate run
# alternatively, you can also reset the database to an empty state
cargo sqlx db reset
```

Make sure the VTN has the necessary user accounts prepared to run the client (VEN) tests.
For that, please apply the corresponding fixture
```bash
psql postgres://openadr:openadr@localhost:5432/openadr < fixtures/users.sql
```

Then, run the tests with the `live-db-test` feature enabled
```bash
cargo test --features=live-db-test [--workspace]
```

### Note on prepared SQL

This workspace uses SQLX macro to type check SQL statements.
In order to build the crate without a running SQL server (such as in the docker), SQLX must be run in offline mode.
In this mode type checking is done via a cached variant of the DB (the .sqlx directory).
For this to work as intended, each time a change is made to SQL schemas or queries, please run

```bash
cargo sqlx prepare --workspace
```

This will update the cached SQL in the `.sqlx` directory which should be committed to GitHub.

### Invalidating the docker build cache

To expedite the slow cargo release builds, the Dockerfile uses a multi-stage build.
If changes have been made and are not being reflected in the binary running inside docker, try

```bash
docker compose up --force-recreate --build --no-deps vtn
```

This will force a rebuild

---

## Post-Quantum Non-Repudiation (fork addition)

This fork integrates the [`nonrep-rs`](https://github.com/horaciog1/nonrep-rs)
library to add post-quantum non-repudiation to all VTN/VEN message exchanges.
Every event dispatched by the VTN and every report submitted by a VEN is
automatically recorded into a per-VEN hash chain signed with ML-DSA-44
(NIST FIPS 204 / Dilithium3).

### Dependency

Add the following to `openleadr-vtn/Cargo.toml`:

```toml
[dependencies]
nonrep = { path = "../nonrep-rs" }
```

Build with the real ML-DSA-44 signer (requires cmake + liboqs):

```bash
BINDGEN_EXTRA_CLANG_ARGS="-I/usr/lib/gcc/x86_64-linux-gnu/$(gcc -dumpversion)/include" \
    cargo build --features pqc
```

Omit `--features pqc` to build with the mock SHA3-512 signer for development
and testing.

### New REST endpoints

Three endpoints are added under `/nonrep`. They sit alongside the standard
OpenADR routes and are served by the same VTN binary.

#### `GET /nonrep/public-key`

Returns the VTN's ML-DSA-44 public key. Any authenticated client may call this.

**Response**

```json
{
  "publicKey": "<base64-encoded ML-DSA-44 public key>",
  "algorithm": "ML-DSA-44",
  "encoding":  "base64"
}
```

---

#### `GET /nonrep/sessions/{venID}/evidence`

Finalises the non-repudiation session for `{venID}` and returns the signed
Evidence object together with the raw payloads and nonces needed to build a
Proof. Requires `read_all`, `read_ven_objects`, or `read_targets` OAuth scope.

`{venID}` is the VEN's OAuth `client_id`, not the OpenADR object ID.

**Response**

```json
{
  "sessionKey":  "<base64>",
  "nonces":      ["<base64>", ...],
  "payloads":    ["<base64>", ...],
  "evidence": {
    "venId":          "<ven_cid>",
    "signingAlg":     "ML-DSA-44",
    "hashChainFinal": "<base64>",
    "signature":      "<base64>",
    "publicKey":      "<base64>",
    "orderingVector": [true, false, true, ...],
    "timestampStart": "<ISO 8601>",
    "timestampEnd":   "<ISO 8601>",
    "recordCount":    5,
    "chunkSize":      16,
    "keyLen":         32
  }
}
```

The `orderingVector` indicates, per record, whether the VTN was the generator
(`true` = event, VTN → VEN) or the VEN was the generator (`false` = report,
VEN → VTN).

---

#### `POST /nonrep/sessions/{venID}/verify`

Verifies a Proof submitted by the caller. Any authenticated client may call
this. Returns HTTP 403 if the `ven_id` field inside the Evidence does not match
the `{venID}` path parameter — this prevents cross-VEN proof substitution.

**Request body**

```json
{
  "evidence": { ... },
  "records":  [ ... ]
}
```

**Response**

```json
{
  "venId": "<ven_cid>",
  "valid": true
}
```

---

### Session key design

Non-repudiation sessions are keyed by the VEN's OAuth `client_id` (`ven_cid`).
This single value threads through all three integration points:

| Integration point             | How `ven_cid` is resolved                                                                                                                                    |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Event hook (`api/event.rs`)   | Each `Target` string in the event's target list is treated as a VEN `client_id`; `record_event_nonrep` calls `nonrep.record_message(target, &payload, true)` |
| Report hook (`api/report.rs`) | `user.client_id()` from the authenticated VEN token; `record_report_nonrep` calls `nonrep.record_message(&ven_id, &payload, false)`                          |
| Evidence / verify endpoints   | `{venID}` path parameter must equal `ven_cid`                                                                                                                |

This means events **must be targeted at the VEN's OAuth `client_id`**, not at
the OpenADR object ID or VEN name. Reports are keyed automatically from the
token, so no special handling is required on the VEN side.

### Key files

| File                    | Purpose                                                                   |
| ----------------------- | ------------------------------------------------------------------------- |
| `src/nonrep_manager.rs` | `NonRepManager` singleton; one `EvidenceGenerator` per active VEN session |
| `src/nonrep_api.rs`     | Handler functions for the three REST endpoints                            |
| `src/api/event.rs`      | `record_event_nonrep` hook called on every create/update                  |
| `src/api/report.rs`     | `record_report_nonrep` hook called on every create/update                 |

### End-to-end testing

See `examples/e2e_live.rs` in the
[nonrep-rs](https://github.com/horaciog1/nonrep-rs) repository for a
self-contained demo that authenticates as both BL and VEN, exchanges real
OpenADR messages, and then exercises the full non-repudiation workflow
(evidence fetch → proof construction → local + server-side verification →
tamper detection) against this VTN.