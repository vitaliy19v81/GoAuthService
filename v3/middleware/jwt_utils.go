// v3/middleware/jwt_utils.go
package middleware

import (
	"apiP/v3/config"
	"github.com/golang-jwt/jwt/v5"
	"time"
)

var (
	JwtKey        = []byte(config.JwtRefreshSecretKey) // Секретный ключ Access
	JwtRefreshKey = []byte(config.JwtRefreshSecretKey) // Секретный ключ Refresh
)

// Claims для создания access токенов
type Claims struct {
	UserID string `json:"userid"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

// GenerateJWT Генерация JWT токена
func GenerateJWT(userID, role string) (string, error) {
	claims := Claims{
		UserID: userID,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "apiP/v3",
			Subject:   userID,
			Audience:  []string{"api"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)), // 1 час time.Hour
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(JwtKey)
}

// GenerateRefreshToken Генерация Refresh Token
func GenerateRefreshToken(userID string, role string) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour) // Срок действия 24 часа
	claims := &Claims{
		UserID: userID,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime), // 24 часа
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(JwtRefreshKey)
}

//func ValidateJWT(tokenString string) (*jwt.MapClaims, error) {
//	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
//		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
//			return nil, fmt.Errorf("unexpected signing method")
//		}
//		return []byte(config.JwtSecretKey), nil
//	})
//
//	if err != nil {
//		return nil, err
//	}
//
//	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
//		return &claims, nil
//	}
//
//	return nil, fmt.Errorf("invalid token")
//}
