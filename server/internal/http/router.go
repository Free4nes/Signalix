package http

import (
	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/signalix/server/internal/auth"
	"github.com/signalix/server/internal/http/handlers"
	"github.com/signalix/server/internal/middleware"
	"github.com/signalix/server/internal/repo"
)

// NewRouter creates a new HTTP router with all routes configured
func NewRouter(authHandler *handlers.AuthHandler, jwtService *auth.JWTService, userRepo repo.UserRepo) *chi.Mux {
	r := chi.NewRouter()

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

	// Protected routes (require valid JWT)
	r.Group(func(r chi.Router) {
		r.Use(middleware.AuthMiddleware(jwtService, userRepo))
		r.Get("/me", authHandler.HandleMe)
	})

	return r
}
