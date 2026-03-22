package main

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/pressly/goose/v3"
	"github.com/signalix/server/internal/auth"
	"github.com/signalix/server/internal/chat"
	"github.com/signalix/server/internal/config"
	"github.com/signalix/server/internal/db"
	httphandler "github.com/signalix/server/internal/http"
	"github.com/signalix/server/internal/http/handlers"
	"github.com/signalix/server/internal/ingest"
	"github.com/signalix/server/internal/project"
	"github.com/signalix/server/internal/ratelimit"
	"github.com/signalix/server/internal/repo"
	"github.com/signalix/server/internal/ws"
)

// ensureEnvFromExample copies .env.example to .env if .env is missing (dev bootstrap)
func ensureEnvFromExample() {
	candidates := []struct{ env, example string }{
		{".env", ".env.example"},
		{"server/.env", "server/.env.example"},
	}
	for _, p := range candidates {
		if _, err := os.Stat(p.env); err == nil {
			return // .env exists
		}
		ex, err := os.Open(p.example)
		if err != nil {
			continue
		}
		defer ex.Close()
		env, err := os.Create(p.env)
		if err != nil {
			continue
		}
		_, _ = io.Copy(env, ex)
		env.Close()
		log.Printf("Created %s from %s", p.env, p.example)
		return
	}
}

func main() {
	// Ensure .env exists: copy from .env.example if missing (works from server/ or repo root)
	ensureEnvFromExample()

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
	refreshRepo := repo.NewRefreshRepo(database)
	projectRepo := repo.NewProjectRepo(database)
	projectKeyRepo := repo.NewProjectKeyRepo(database)
	eventRepo := repo.NewEventRepo(database)
	projectEventRepo := repo.NewProjectEventRepo(database)
	conversationRepo := repo.NewConversationRepo(database, userRepo)
	messageRepo := repo.NewMessageRepo(database)
	pushTokenRepo := repo.NewPushTokenRepo(database)
	reactionRepo := repo.NewReactionRepo(database)
	blockedRepo := repo.NewBlockedRepo(database)

	// Initialize auth services
	var otpProvider auth.OtpProvider
	if cfg.OTPDevMode {
		otpProvider = auth.NewOtpStub(otpRepo, cfg.OTPSalt)
		log.Printf("OTP provider: dev stub (OTP_DEV_MODE=true)")
	} else {
		otpProvider = auth.NewTwilioVerifyOtpProvider(
			cfg.TwilioAccountSID,
			cfg.TwilioAuthToken,
			cfg.TwilioVerifyServiceSID,
		)
		log.Printf("OTP provider: Twilio Verify (OTP_DEV_MODE=false)")
	}
	jwtService := auth.NewJWTService(cfg.JWTSecret, cfg.AccessTokenTTL)
	authService := auth.NewAuthService(
		otpProvider,
		jwtService,
		userRepo,
		deviceRepo,
		refreshRepo,
		cfg.RefreshTokenTTL,
	)

	// Initialize project service
	projectSvc := project.NewService(
		database,
		projectRepo,
		projectKeyRepo,
		conversationRepo,
		projectEventRepo,
	)

	// Initialize ingest service
	ingestSvc := ingest.NewService(eventRepo)

	// Initialize chat service
	chatSvc := chat.NewService(
		database,
		userRepo,
		conversationRepo,
		messageRepo,
		projectRepo,
		projectEventRepo,
		reactionRepo,
	)

	// Initialize handlers
	authHandler := handlers.NewAuthHandler(authService, otpProvider, userRepo, pushTokenRepo)
	projectHandler := handlers.NewProjectHandler(projectSvc)
	contactsHandler := handlers.NewContactsHandler(userRepo, cfg.DevAutoCreateUsers)
	ingestHandler := handlers.NewIngestHandler(ingestSvc)
	eventsHandler := handlers.NewEventsHandler(eventRepo, projectRepo)

	hub := ws.NewHub()

	msgLimiter := ratelimit.NewMessageLimiter(20, 10*time.Second)
	msgLimiter.StartCleanup()
	log.Printf("RATE_LIMIT enabled: 20 msg/10s per user (create message + audio)")

	chatHandler := handlers.NewChatHandler(
		chatSvc,
		hub,
		conversationRepo,
		pushTokenRepo,
		userRepo,
		reactionRepo,
		blockedRepo,
		msgLimiter,
	)

	userHandler := handlers.NewUserHandler(blockedRepo)
	wsHandler := handlers.NewWsHandler(hub, jwtService, userRepo, conversationRepo, chatSvc)

	// Create router
	router := httphandler.NewRouter(
		authHandler,
		projectHandler,
		chatHandler,
		wsHandler,
		contactsHandler,
		ingestHandler,
		eventsHandler,
		userHandler,
		projectSvc,
		jwtService,
		userRepo,
	)

	log.Printf("Routes: DELETE /messages/{messageId} (delete), PUT /messages/{messageId} (edit)")

	chi.Walk(router, func(method, route string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		if method == "GET" && (route == "/conversations/{id}" || route == "//conversations/{id}") {
			log.Printf("CONVERSATION_DETAILS route registered: GET %s", route)
		}
		return nil
	})

	// IMPORTANT:
	// Addr ":8080" already means listen on all interfaces (0.0.0.0:8080)
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
		log.Printf("Server listening on 0.0.0.0:%s", cfg.Port)
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

	// Resolve migration dir so it works from server/ or repo root
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
