// v3/handlers/handlers.go
package handlers

import (
	"apiP/v3/middleware"
	"database/sql"
	"github.com/gin-gonic/gin"
	"net/http"
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

// RegisterRequestPhone Модель для документации Swagger
type RegisterRequestPhone struct {
	Phone    *string `json:"phone" binding:"required"`    // Телефон пользователя (обязательно)
	Password *string `json:"password" binding:"required"` // Пароль пользователя (обязательно)
}

// RegisterRequestEmail Модель для документации Swagger
type RegisterRequestEmail struct {
	Email    *string `json:"email" binding:"required"`
	Password *string `json:"password" binding:"required"`
}

// example@example.com
//user.name@sub.domain.com
//user+tag@domain.co.uk
//1234567890@domain.com
//user_name@domain.com
//user-name@domain.io
//user@domain.travel
//email@localhost (при использовании локальных адресов).

// ^\+?: Опциональный символ + в начале.
//\d{0,3}: До трех цифр для кода страны.
//[-\s]?: Опциональный дефис или пробел.
//\(?\d{2,5}\)?: Код города/оператора (2–5 цифр), опционально в скобках.
//[-\s]?: Опциональный дефис или пробел.
//\d{2,4}: Блок из 2–4 цифр (основная часть номера).
//[-\s]?: Опциональный дефис или пробел.
//\d{2,4}: Еще один блок из 2–4 цифр.
//[-\s]?: Опциональный дефис или пробел.
//\d{2,4}$: Последний блок из 2–4 цифр.

// +1-800-555-0199
//+44 20 7946 0958
//+91 (22) 1234-5678
//+33-1-23-45-67-89
//+49 (30) 123 456 7890
//+7 495 123-45-67
//+86 10 1234 5678
//+1 (650) 555 1234
//+61 2 9876 5432
//+234 803 123 4567

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
