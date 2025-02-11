// v3/middleware/auth_middleware.go
package middleware

import (
	"apiP/v3/config"
	"bytes"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
)

var ValidRoles = []string{"user", "editor", "moderator", "admin"} // Роли по возрастанию прав

func RoleIndex(role string) int {
	for i, r := range ValidRoles {
		if r == role {
			return i
		}
	}
	return -1
}

func Contains(roles []string, role string) bool {
	for _, r := range roles {
		if r == role {
			return true
		}
	}
	return false
}

// AuthMiddleware - middleware для проверки JWT токенов и авторизации
func AuthMiddleware(minRole string) gin.HandlerFunc {
	return func(c *gin.Context) {

		authHeader := c.GetHeader("Authorization")

		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing or invalid token"})
			c.Abort()
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("invalid signing method")
			}
			return JwtKey, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		claims, ok := token.Claims.(*Claims)
		if !ok || claims.UserID == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid claims"})
			c.Abort()
			return
		}

		if minRole != "" && RoleIndex(claims.Role) < RoleIndex(minRole) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Forbidden"})
			c.Abort()
			return
		}

		c.Set("userid", claims.UserID)
		c.Set("role", claims.Role)
		c.Next()
	}
}

// RecoveryMiddleware обрабатывает панику и продолжает работу сервера
func RecoveryMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("Recovered from panic: %v", r)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal Server Error"})
			}
		}()
		c.Next()
	}
}

// LoggingMiddleware - middleware для логирования запросов
func LoggingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Логирование параметров запроса
		log.Println("Query params:", c.Request.URL.Query())

		// Логирование заголовков только в режиме разработки
		if config.Environment == "development" {
			log.Println("Headers:", c.Request.Header)
		}

		// Логирование тела запроса только в режиме разработки
		if config.Environment == "development" && c.Request.Body != nil {
			bodyBytes, err := ioutil.ReadAll(c.Request.Body)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка чтения тела запроса"})
				c.Abort()
				return
			}
			log.Println("Request Body:", string(bodyBytes))

			// Восстановление тела запроса для дальнейшей обработки
			c.Request.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
		}

		// Передача управления следующему обработчику
		c.Next()
	}
}

// лог SLOG
//func LoggingMiddleware() gin.HandlerFunc {
//	return func(c *gin.Context) {
//		logger := slog.Default()
//
//		// Логирование параметров запроса
//		logger.Info("Query params", "params", c.Request.URL.Query())
//
//		if config.Environment == "development" {
//			// Логирование заголовков
//			logger.Debug("Headers", "headers", c.Request.Header)
//
//			// Логирование тела запроса
//			if c.Request.Body != nil {
//				bodyBytes, err := ioutil.ReadAll(c.Request.Body)
//				if err != nil {
//					c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка чтения тела запроса"})
//					c.Abort()
//					return
//				}
//				logger.Debug("Request Body", "body", string(bodyBytes))
//
//				// Восстановление тела запроса для дальнейшей обработки
//				c.Request.Body = ioutil.NopCloser(bytes.NewBuffer(bodyBytes))
//			}
//		}
//
//		// Передача управления следующему обработчику
//		c.Next()
//	}
//}
