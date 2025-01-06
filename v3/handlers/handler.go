package handlers

import "apiP/v3/repository"

// NewHandler создает новый обработчик.
func NewHandler(userRepo repository.UserRepository) *Handler {
	return &Handler{userRepo: userRepo}
}

// Handler содержит зависимости для обработки запросов.
type Handler struct {
	userRepo repository.UserRepository
}
