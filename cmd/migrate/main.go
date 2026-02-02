package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	var (
		dsn       = flag.String("dsn", os.Getenv("POSTGRES_DSN"), "PostgreSQL connection string")
		direction = flag.String("direction", "up", "Migration direction: up or down")
		steps     = flag.Int("steps", 0, "Number of migrations to run (0 = all)")
	)
	flag.Parse()

	if *dsn == "" {
		log.Fatal("POSTGRES_DSN is required")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, *dsn)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer pool.Close()

	// Create migrations table if not exists
	_, err = pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`)
	if err != nil {
		log.Fatalf("Failed to create migrations table: %v", err)
	}

	// Get applied migrations
	rows, err := pool.Query(ctx, "SELECT version FROM schema_migrations ORDER BY version")
	if err != nil {
		log.Fatalf("Failed to get applied migrations: %v", err)
	}
	defer rows.Close()

	applied := make(map[string]bool)
	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			log.Fatalf("Failed to scan migration version: %v", err)
		}
		applied[version] = true
	}

	// Find migration files
	migrationsDir := "migrations"
	if _, err := os.Stat(migrationsDir); os.IsNotExist(err) {
		// Try relative to executable
		execPath, _ := os.Executable()
		migrationsDir = filepath.Join(filepath.Dir(execPath), "migrations")
	}

	suffix := ".up.sql"
	if *direction == "down" {
		suffix = ".down.sql"
	}

	files, err := filepath.Glob(filepath.Join(migrationsDir, "*"+suffix))
	if err != nil {
		log.Fatalf("Failed to find migration files: %v", err)
	}

	// Sort files
	sort.Strings(files)
	if *direction == "down" {
		// Reverse order for down migrations
		for i, j := 0, len(files)-1; i < j; i, j = i+1, j-1 {
			files[i], files[j] = files[j], files[i]
		}
	}

	// Run migrations
	count := 0
	for _, file := range files {
		base := filepath.Base(file)
		version := strings.TrimSuffix(base, suffix)

		if *direction == "up" {
			if applied[version] {
				continue
			}
		} else {
			if !applied[version] {
				continue
			}
		}

		if *steps > 0 && count >= *steps {
			break
		}

		fmt.Printf("Running migration: %s\n", base)

		content, err := os.ReadFile(file)
		if err != nil {
			log.Fatalf("Failed to read migration file %s: %v", file, err)
		}

		tx, err := pool.Begin(ctx)
		if err != nil {
			log.Fatalf("Failed to begin transaction: %v", err)
		}

		_, err = tx.Exec(ctx, string(content))
		if err != nil {
			tx.Rollback(ctx)
			log.Fatalf("Failed to execute migration %s: %v", file, err)
		}

		if *direction == "up" {
			_, err = tx.Exec(ctx, "INSERT INTO schema_migrations (version) VALUES ($1)", version)
		} else {
			_, err = tx.Exec(ctx, "DELETE FROM schema_migrations WHERE version = $1", version)
		}
		if err != nil {
			tx.Rollback(ctx)
			log.Fatalf("Failed to update migrations table: %v", err)
		}

		if err := tx.Commit(ctx); err != nil {
			log.Fatalf("Failed to commit transaction: %v", err)
		}

		fmt.Printf("Applied migration: %s\n", version)
		count++
	}

	if count == 0 {
		fmt.Println("No migrations to apply")
	} else {
		fmt.Printf("Applied %d migration(s)\n", count)
	}
}
