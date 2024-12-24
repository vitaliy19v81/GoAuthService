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

//// это лишнее
//// RefreshRefreshToken — обновляет сам Refresh токен и сохраняет в cookie
//func RefreshRefreshToken(c *gin.Context) {
//	// Проверяем наличие старого refresh токена
//	oldRefreshToken, err := c.Cookie("refreshToken")
//	if err != nil {
//		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing refresh token"})
//		return
//	}
//
//	// Проверяем старый refresh токен
//	claims, err := validateRefreshToken(oldRefreshToken)
//	if err != nil {
//		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
//		return
//	}
//
//	// Генерация нового refresh токена
//	newRefreshToken, err := middleware.GenerateRefreshToken(claims.UserID, claims.Role)
//	if err != nil {
//		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate new refresh token"})
//		return
//	}
//
//	// Устанавливаем новый refresh токен в cookie
//	//c.SetCookie("refreshToken", newRefreshToken, 24*3600, "/", "", true, true)
//
//	// Устанавливаем refreshToken как HttpOnly cookie
//	http.SetCookie(c.Writer, &http.Cookie{
//		Name:     "refreshToken",
//		Value:    newRefreshToken,
//		Path:     "/",
//		HttpOnly: true,
//		Secure:   false, // Для локальной разработки
//		SameSite: http.SameSiteLaxMode,
//	})
//	c.JSON(http.StatusOK, gin.H{"message": "Refresh token updated"})
//}

// рабочая версия
//// RefreshAccessToken — обработчик для обновления токенов
//func RefreshAccessToken(c *gin.Context) {
//	refreshToken, err := c.Cookie("refreshToken")
//	//log.Println(refreshToken)
//
//	if err != nil {
//		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing refresh token"})
//		return
//	}
//
//	// Проверка refresh токена
//	claims := &middleware.Claims{}
//	token, err := jwt.ParseWithClaims(refreshToken, claims, func(token *jwt.Token) (interface{}, error) {
//		return middleware.JwtKey, nil
//	})
//	if err != nil || !token.Valid {
//		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
//		return
//	}
//
//	//// Генерация refresh токена
//	//refreshToken, err = middleware.GenerateRefreshToken(refreshClaims.Username)
//	//if err != nil {
//	//	c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при генерации refresh токена"})
//	//	return
//	//}
//
//	// Генерация нового access токена
//	accessToken, err := middleware.GenerateJWT(claims.UserID, claims.Role)
//	if err != nil {
//		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate access token"})
//		return
//	}
//
//	// c.SetCookie("authToken", newAuthToken, 3600, "/", "", true, true)
//	// c.SetCookie("refreshToken", newRefreshToken, 86400, "/", "", true, true)
//	//
//	// Отправляем новые токены в заголовках
//	c.Header("AuthToken", accessToken)
//	//c.Header("RefreshToken", refreshToken)
//
//	c.JSON(http.StatusOK, gin.H{"message": "Tokens refreshed"})
//}

////////////////////////////////////////////////////////////////////////////////////////

//// RefreshTokenHandlerDB Реализует обновление токена
//func RefreshTokenHandlerDB(db *sql.DB) gin.HandlerFunc {
//	return func(c *gin.Context) {
//		// Читаем refresh токен из тела запроса
//		var req struct {
//			RefreshToken string `json:"refresh_token"`
//		}
//		if err := c.BindJSON(&req); err != nil {
//			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
//			return
//		}
//
//		// Проверяем наличие токена в базе данных
//		var username string
//		err := db.QueryRow("SELECT username FROM refresh_tokens WHERE token = $1", req.RefreshToken).Scan(&username)
//		if err == sql.ErrNoRows {
//			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired refresh token"})
//			return
//		} else if err != nil {
//			c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
//			return
//		}
//
//		// Генерируем новый Access Token
//		newToken, err := middleware.GenerateJWT(username, "user")
//		if err != nil {
//			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
//			return
//		}
//
//		c.JSON(http.StatusOK, gin.H{"token": newToken})
//
//		//// Удаляем сохранение в куки
//		//// c.SetCookie("authToken", newAuthToken, 3600, "/", "", true, true)
//		//// c.SetCookie("refreshToken", newRefreshToken, 86400, "/", "", true, true)
//		//
//		//// Отправляем новые токены в заголовках
//		//c.Header("AuthToken", newAuthToken)
//		//c.Header("RefreshToken", newRefreshToken)
//		//
//		//c.JSON(http.StatusOK, gin.H{"message": "Tokens refreshed"})
//	}
//}
