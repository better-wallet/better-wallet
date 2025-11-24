#!/bin/bash

# Migration script for Better Wallet
# Usage: ./scripts/migrate.sh [up|down]

set -e

# Load environment variables if .env exists
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

# Check if POSTGRES_DSN is set
if [ -z "$POSTGRES_DSN" ]; then
    echo "Error: POSTGRES_DSN environment variable is not set"
    echo "Please set it in .env file or export it manually"
    exit 1
fi

# Parse database connection string to get database name
DB_NAME=$(echo $POSTGRES_DSN | sed -n 's/.*\/\([^?]*\).*/\1/p')

if [ -z "$DB_NAME" ]; then
    echo "Error: Could not extract database name from POSTGRES_DSN"
    exit 1
fi

echo "Database: $DB_NAME"

# Function to run migrations up
migrate_up() {
    echo "Running migrations up..."
    for file in migrations/*up.sql; do
        if [ -f "$file" ]; then
            echo "Applying: $file"
            psql "$POSTGRES_DSN" -f "$file"
        fi
    done
    echo "Migrations completed successfully!"
}

# Function to run migrations down
migrate_down() {
    echo "Rolling back migrations..."
    for file in migrations/*down.sql; do
        if [ -f "$file" ]; then
            echo "Rolling back: $file"
            psql "$POSTGRES_DSN" -f "$file"
        fi
    done
    echo "Rollback completed successfully!"
}

# Function to create database if it doesn't exist
create_db() {
    echo "Creating database if it doesn't exist..."
    # Extract connection info without database name
    HOST=$(echo $POSTGRES_DSN | sed -n 's/.*@\([^:\/]*\).*/\1/p')
    PORT=$(echo $POSTGRES_DSN | sed -n 's/.*:\([0-9]*\)\/.*/\1/p')
    USER=$(echo $POSTGRES_DSN | sed -n 's/.*\/\/\([^:]*\):.*/\1/p')

    # Try to create database
    psql "postgres://$USER@$HOST:$PORT/postgres" -c "CREATE DATABASE $DB_NAME;" 2>/dev/null || echo "Database already exists or couldn't be created"
}

# Main script logic
case "${1:-up}" in
    up)
        create_db
        migrate_up
        ;;
    down)
        migrate_down
        ;;
    create)
        create_db
        ;;
    *)
        echo "Usage: $0 [up|down|create]"
        echo "  up     - Run all pending migrations (default)"
        echo "  down   - Rollback all migrations"
        echo "  create - Create the database"
        exit 1
        ;;
esac
