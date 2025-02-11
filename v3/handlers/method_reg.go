package handlers

import (
	"apiP/v3/config"
	"github.com/gin-gonic/gin"
	"net/http"
	"sync"
)

var (
	requiredFields = []string{"username", "password"} // Начальный список обязательных полей
	fieldsMutex    sync.RWMutex                       // Для обеспечения потокобезопасности
)

// GetRequiredFieldsHandler возвращает текущий список обязательных полей
func GetRequiredFieldsHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		fields := config.GetRequiredFields() // Используем функцию из config.go
		c.JSON(http.StatusOK, gin.H{"required_fields": fields})
	}
}

// SetRequiredFieldsHandler обновляет список обязательных полей
func SetRequiredFieldsHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		var body struct {
			Fields []string `json:"fields"`
		}

		if err := c.ShouldBindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}

		// Валидация списка полей
		validFields := map[string]bool{
			"username": true,
			"email":    true,
			"phone":    true,
			"password": true,
		}
		for _, field := range body.Fields {
			if !validFields[field] {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid field: " + field})
				return
			}
		}

		fieldsMutex.Lock()
		requiredFields = body.Fields
		fieldsMutex.Unlock()

		c.JSON(http.StatusOK, gin.H{"message": "Required fields updated"})
	}
}
