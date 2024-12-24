// v3/handlers/handlers.go
package handlers

import (
	"apiP/v3/middleware"
	"database/sql"
	"github.com/gin-gonic/gin"
	"net/http"
	"regexp"
)

type LoginRequest struct {
	Username *string `json:"username,omitempty"`
	Password *string `json:"password"`
	Email    *string `json:"email,omitempty"`
	Phone    *string `json:"phone,omitempty"`
}

type RegisterRequest struct {
	Username *string `json:"username,omitempty"`
	Password *string `json:"password"`
	Email    *string `json:"email,omitempty"`
	Phone    *string `json:"phone,omitempty"`
}

var (
	EmailRegex = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)                                             // Валидация email
	PhoneRegex = regexp.MustCompile(`^\+?\d{0,3}[-\s]?\(?\d{2,5}\)?[-\s]?\d{2,4}[-\s]?\d{2,4}[-\s]?\d{2,4}$`) // Валидация телефона
)

func AssignRoleHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {

		// Читаем запрос
		var req struct {
			Username string `json:"username"`
			Role     string `json:"role"`
		}

		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
			return
		}

		// Проверяем, существует ли пользователь
		var userExists bool
		err := db.QueryRow("SELECT EXISTS (SELECT 1 FROM users WHERE username = $1)", req.Username).Scan(&userExists)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
			return
		}
		if !userExists {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}

		// Проверяем, является ли роль валидной
		if !middleware.Contains(middleware.ValidRoles, req.Role) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid role"})
			return
		}

		// Обновляем роль пользователя
		_, err = db.Exec("UPDATE users SET role = $1 WHERE username = $2", req.Role, req.Username)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update role"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Role updated successfully"})
	}
}

func ProtectedHandler(c *gin.Context) {
	username, _ := c.Get("username")
	role, _ := c.Get("role")
	c.JSON(http.StatusOK, gin.H{"message": "Welcome to the protected route!", "user": username, "role": role})
}

func EditorHandler(c *gin.Context) {
	username, _ := c.Get("username")
	c.JSON(http.StatusOK, gin.H{"message": "Editor access granted", "user": username})
}
