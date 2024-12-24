package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// LogoutHandler — обработчик для выхода пользователя
func LogoutHandler(c *gin.Context) {
	// Удаляем токены из куки, устанавливая срок действия в прошлое
	c.SetCookie("authToken", "", -1, "/", "", true, true)
	c.SetCookie("refreshToken", "", -1, "/", "", true, true)

	// (Опционально) Добавить текущие токены в "черный список" (в базе или в памяти)

	// Отправляем ответ клиенту
	c.JSON(http.StatusOK, gin.H{"message": "Successfully logged out"})
}
