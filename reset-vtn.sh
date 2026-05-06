#!/bin/bash

set -euo pipefail

DB_CONTAINER_NAME="db"
DB_USER="openadr"
DB_PASSWORD="openadr"
DB_NAME="openadr"
DB_HOST="localhost"
FIXTURES_FILE="fixtures/users.sql"

wait_for_postgres() {
    echo "Waiting for PostgreSQL..."

    until PGPASSWORD="$DB_PASSWORD" psql \
        -U "$DB_USER" \
        -h "$DB_HOST" \
        -d "$DB_NAME" \
        -c "SELECT 1;" >/dev/null 2>&1; do

        sleep 2
        echo "Still waiting..."
    done

    echo "PostgreSQL is fully ready."
}

echo "Bringing down containers and wiping volumes..."
docker compose down -v

echo "Starting database..."
docker compose up -d "$DB_CONTAINER_NAME"

wait_for_postgres

echo "Running SQLx migrations..."
DATABASE_URL="postgres://${DB_USER}:${DB_PASSWORD}@${DB_HOST}/${DB_NAME}" \
cargo sqlx migrate run

echo "Loading fixtures..."
PGPASSWORD="$DB_PASSWORD" \
psql -U "$DB_USER" -h "$DB_HOST" -d "$DB_NAME" -f "$FIXTURES_FILE"

echo "Starting VTN..."
BINDGEN_EXTRA_CLANG_ARGS="-I/usr/lib/gcc/x86_64-linux-gnu/$(gcc -dumpversion)/include" \
DATABASE_URL="postgres://${DB_USER}:${DB_PASSWORD}@${DB_HOST}/${DB_NAME}" \
cargo run -p openleadr-vtn --features internal-oauth,pqc