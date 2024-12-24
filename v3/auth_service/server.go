// /home/vtoroy/GolandProjects/apiP/v3/auth_service/main.go
package auth

import (
	pb "apiP/v3/internal/services/auth_proto"
	"apiP/v3/middleware"
	"context"
	"github.com/golang-jwt/jwt/v5"
)

type ServiceAuthServer struct {
	pb.UnimplementedAuthServiceServer // Встраивание gRPC-сервера с пустой реализацией
}

func (s *ServiceAuthServer) ValidateToken(ctx context.Context, req *pb.ValidateTokenRequest) (*pb.ValidateTokenResponse, error) {
	tokenString := req.Token

	// Парсим токен
	token, err := jwt.ParseWithClaims(tokenString, &middleware.Claims{}, func(token *jwt.Token) (interface{}, error) {
		return middleware.JwtKey, nil
	})
	if err != nil || !token.Valid {
		return &pb.ValidateTokenResponse{
			Valid: false,
			Error: "Invalid token",
		}, nil
	}

	// Извлекаем claims
	claims, ok := token.Claims.(*middleware.Claims)
	if !ok {
		return &pb.ValidateTokenResponse{
			Valid: false,
			Error: "Invalid claims",
		}, nil
	}

	return &pb.ValidateTokenResponse{
		Valid:  true,
		UserId: claims.UserID,
		Role:   claims.Role,
	}, nil
}

// NewAuthServiceServer создаёт экземпляр AuthServiceServer
func NewAuthServiceServer() *ServiceAuthServer {
	return &ServiceAuthServer{}
}
