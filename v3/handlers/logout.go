package handlers

import (
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
	"strings"
)

// LogoutHandler — обработчик для выхода пользователя
func (h *Handler) LogoutHandler(c *gin.Context) {
	// Получаем токен из заголовка Authorization
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		log.Println("Токен отсутствует")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Токен отсутствует"})
		return
	}

	// Извлекаем сам токен без "Bearer "
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		log.Println("Неверный формат токена")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный формат токена"})
		return
	}
	token := parts[1]

	// (Опционально) Добавить текущие токены в "черный список" (в базе или в памяти)
	if err := h.userRepo.InsertToBlackList(token); err != nil {
		log.Println("Ошибка при сохранении токена в черный список")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка сервера"})
		return
	}

	// Удаляем токены из куки, устанавливая срок действия в прошлое
	c.SetCookie("authToken", "", -1, "/", "", true, true)
	c.SetCookie("refreshToken", "", -1, "/", "", true, true)

	// Отправляем ответ клиенту
	c.JSON(http.StatusOK, gin.H{"message": "Successfully logged out"})
}
