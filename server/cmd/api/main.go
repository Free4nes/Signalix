package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"github.com/pressly/goose/v3"
	"github.com/signalix/server/internal/auth"
	"github.com/signalix/server/internal/config"
	"github.com/signalix/server/internal/db"
	httphandler "github.com/signalix/server/internal/http"
	"github.com/signalix/server/internal/http/handlers"
	"github.com/signalix/server/internal/repo"
	_ "github.com/lib/pq"
)

func main() {
	// Load .env from CWD or server/ so it works from repo root or server/ (env vars override)
	_ = godotenv.Load(".env")
	_ = godotenv.Load("server/.env")

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Create context for startup operations
	ctx := context.Background()

	// Open database connection
	database, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer database.Close()

	// Run migrations
	if err := runMigrations(database); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}

	// Initialize repositories
	userRepo := repo.NewUserRepo(database)
	deviceRepo := repo.NewDeviceRepo(database)
	otpRepo := repo.NewOtpRepo(database)

	// Initialize auth services
	otpProvider := auth.NewOtpStub(otpRepo, cfg.OTPSalt)
	jwtService := auth.NewJWTService(cfg.JWTSecret)
	authService := auth.NewAuthService(otpProvider, jwtService, userRepo, deviceRepo)

	// Initialize handlers
	authHandler := handlers.NewAuthHandler(authService, otpProvider)

	// Create router
	router := httphandler.NewRouter(authHandler, jwtService, userRepo)

	// Create HTTP server with timeouts
	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		log.Printf("Server starting on port %s", cfg.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed to start: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	// Graceful shutdown with timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exited")
}

// runMigrations runs database migrations using goose
func runMigrations(database *sql.DB) error {
	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("failed to set goose dialect: %w", err)
	}

	// Resolve migration dir so it works from server/ or repo root (e.g. Windows PowerShell)
	migrationDir := "internal/db/migrations"
	if info, err := os.Stat(migrationDir); err != nil || !info.IsDir() {
		migrationDir = "server/internal/db/migrations"
	}
	if info, err := os.Stat(migrationDir); err != nil || !info.IsDir() {
		return fmt.Errorf("migrations directory not found (run from server/ or repo root)")
	}

	absDir, _ := filepath.Abs(migrationDir)
	log.Printf("Running migrations from %s", absDir)

	if err := goose.Up(database, migrationDir); err != nil {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	return nil
}
