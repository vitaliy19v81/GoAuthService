// v3/handlers/refresh.go
package handlers

import (
	"apiP/v3/middleware"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"net/http"
)

// Проверяем refresh токен и возвращаем claims или ошибку
func validateRefreshToken(refreshToken string) (*middleware.Claims, error) {
	claims := &middleware.Claims{}
	token, err := jwt.ParseWithClaims(refreshToken, claims, func(token *jwt.Token) (interface{}, error) {
		return middleware.JwtKey, nil
	})

	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}

// RefreshAccessToken — обработчик для обновления токенов
func RefreshAccessToken(c *gin.Context) {
	// Получаем refreshToken из cookie
	refreshToken, err := c.Cookie("refreshToken")
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing refresh token"})
		return
	}

	// Проверяем refresh токен с помощью новой функции
	claims, err := validateRefreshToken(refreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
		return
	}

	// Генерация нового access токена
	accessToken, err := middleware.GenerateJWT(claims.UserID, claims.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate access token"})
		return
	}

	// Отправляем токен в заголовке
	c.Header("AuthToken", accessToken)
	c.JSON(http.StatusOK, gin.H{"message": "Tokens refreshed"})
}
