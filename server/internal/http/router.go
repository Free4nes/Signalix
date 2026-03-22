package http

import (
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/signalix/server/internal/auth"
	"github.com/signalix/server/internal/http/handlers"
	"github.com/signalix/server/internal/middleware"
	"github.com/signalix/server/internal/project"
	"github.com/signalix/server/internal/repo"
)

// NewRouter creates a new HTTP router with all routes configured
func NewRouter(
	authHandler *handlers.AuthHandler,
	projectHandler *handlers.ProjectHandler,
	chatHandler *handlers.ChatHandler,
	wsHandler *handlers.WsHandler,
	contactsHandler *handlers.ContactsHandler,
	ingestHandler *handlers.IngestHandler,
	eventsHandler *handlers.EventsHandler,
	userHandler *handlers.UserHandler,
	projectSvc *project.Service,
	jwtService *auth.JWTService,
	userRepo repo.UserRepo,
) *chi.Mux {
	r := chi.NewRouter()

	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"http://localhost:3000", "http://localhost:8081", "http://127.0.0.1:8081"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Authorization", "Content-Type", "X-API-Key"},
		AllowCredentials: false,
	}))

	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)
	r.Use(chimw.Logger)
	r.Use(chimw.Recoverer)

	healthHandler := handlers.NewHealthHandler()
	r.Get("/health", healthHandler.ServeHTTP)

	r.Route("/auth", func(r chi.Router) {
		r.Post("/request_otp", authHandler.HandleRequestOTP)
		r.Post("/verify_otp", authHandler.HandleVerifyOTP)
		r.Post("/refresh", authHandler.HandleRefresh)
		r.Post("/logout", authHandler.HandleLogout)
	})

	// WebSocket: auth via ?token= or Authorization header (browsers cannot set headers for WS upgrade)
	r.Get("/ws", wsHandler.ServeHTTP)

	// Protected routes (require valid JWT)
	r.Group(func(r chi.Router) {
		r.Use(middleware.AuthMiddleware(jwtService, userRepo))
		r.Post("/upload", chatHandler.HandleUploadImage)
		r.Get("/users/blocked", userHandler.HandleGetBlockedUsers)

		r.Route("/me", func(r chi.Router) {
			r.Get("/", authHandler.HandleMe)
			r.Patch("/", authHandler.HandlePatchMe)
			r.Put("/avatar", authHandler.HandlePutMeAvatar)
			r.Post("/push-token", authHandler.HandleSavePushToken)
		})

		r.Route("/projects", func(r chi.Router) {
			r.Post("/", projectHandler.HandleCreateProject)
			r.Get("/", projectHandler.HandleListProjects)
			r.Route("/{projectId}", func(r chi.Router) {
			r.Get("/", projectHandler.HandleGetProject)
			r.Delete("/", projectHandler.HandleArchiveProject)
			r.Post("/archive", projectHandler.HandleSoftArchiveProject)
				r.Get("/events", eventsHandler.HandleListEvents)
				r.Get("/activity", projectHandler.HandleListProjectEvents)
				r.Route("/keys", func(r chi.Router) {
					r.Post("/", projectHandler.HandleCreateKey)
					r.Get("/", projectHandler.HandleListKeys)
					r.Post("/{keyId}/revoke", projectHandler.HandleRevokeKey)
				})
			})
		})

		r.Route("/users", func(r chi.Router) {
			r.Post("/block", userHandler.HandleBlock)
			r.Delete("/block/{blockedUserId}", userHandler.HandleUnblock)
			r.Get("/{userId}/online-status", chatHandler.HandleGetUserOnlineStatus)
		})

		r.Route("/contacts", func(r chi.Router) {
			r.Post("/lookup", contactsHandler.HandleLookup)
			r.Post("/sync", contactsHandler.HandleSync)
		})

		r.Route("/messages", func(r chi.Router) {
			r.Put("/{messageId}", chatHandler.HandleEditMessage)
			r.Delete("/{messageId}", chatHandler.HandleDeleteMessageByID)
		})

		r.Route("/conversations", func(r chi.Router) {
			r.Post("/", chatHandler.HandleCreateConversation)
			r.Get("/", chatHandler.HandleListConversations)
			r.Route("/{id}", func(r chi.Router) {
				r.Get("/", chatHandler.HandleGetConversation)
				r.Patch("/", chatHandler.HandlePatchConversation)
				r.Post("/members", chatHandler.HandleAddMember)
				r.Delete("/members/{userId}", chatHandler.HandleRemoveMember)
				r.Get("/messages", chatHandler.HandleListMessages)
				r.Delete("/messages", chatHandler.HandleClearConversationMessages)
				r.Get("/messages/search", chatHandler.HandleSearchMessages)
				r.Post("/messages", chatHandler.HandleCreateMessage)
				r.Delete("/messages/{messageId}", chatHandler.HandleDeleteMessage)
				r.Post("/audio", chatHandler.HandleUploadAudio)
			})
		})
	})

	// API-key protected routes (X-API-Key header, no JWT required)
	r.Route("/ingest", func(r chi.Router) {
		r.Use(middleware.APIKeyMiddleware(projectSvc))
		r.Post("/", ingestHandler.HandleIngest)
	})

	// Static file serving for uploaded audio files (read-only, no auth required for playback URLs)
	uploadsDir := "/app/uploads"
	if _, err := os.Stat("/app"); os.IsNotExist(err) {
		uploadsDir = "uploads"
	}
	fs := http.FileServer(http.Dir(uploadsDir))
	r.Handle("/uploads/*", http.StripPrefix("/uploads", fs))

	return r
}
