package handlers

import (
	"apiP/v3/config"
	"apiP/v3/dto"
	"apiP/v3/middleware"
	"apiP/v3/security"
	"github.com/gin-gonic/gin"
	"net/http"
	"strconv"
)

// GetUsersHandler возвращает список пользователей.
// @Summary Получение списка пользователей
// @Description Возвращает список пользователей с информацией о роли, статусе и времени регистрации. Требуется авторизация через Bearer Token.
// @Tags users
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer токен" example("Bearer your_token")
// @Param length query int false "Количество записей для возврата (по умолчанию 10)"
// @Param start query int false "Смещение записей (по умолчанию 0)"
// @Success 200 {object} SuccessResponse
// @Failure 400 {object} ErrorResponse "Некорректные параметры запроса"
// @Failure 500 {object} ErrorResponse "Ошибка при подсчёте общего числа записей"
// @Security BearerAuth
// @Router /api/auth/admin/users [get]
func (h *Handler) GetUsersHandler(c *gin.Context) {
	limitStr := c.DefaultQuery("length", "10")
	offsetStr := c.DefaultQuery("start", "0")

	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit <= 0 {
		limit = 10
	}
	offset, err := strconv.Atoi(offsetStr)
	if err != nil || offset < 0 {
		offset = 0
	}

	users, totalRecords, err := h.userRepo.GetUsers(limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при получении пользователей"})
		return
	}

	c.JSON(http.StatusOK, SuccessResponse{
		Data:         users,
		TotalRecords: totalRecords,
		Limit:        limit,
		Offset:       offset,
	})
}

// UpdateUserHandler обновляет данные пользователя.
// @Summary Обновление данных пользователя
// @Description Обновляет имя и роль пользователя. Требуется авторизация через Bearer Token.
// @Tags users
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer токен" example("Bearer your_token")
// @Param id path string true "ID пользователя"
// @Param input body UpdateUserRequest true "Данные для обновления пользователя"
// @Success 200 {object} MessageResponse{message=string}
// @Failure 400 {object} ErrorResponse "Некорректные данные запроса"
// @Failure 500 {object} ErrorResponse "Ошибка обновления пользователя"
// @Security BearerAuth
// @Router /api/auth/admin/users/{id} [put]
func (h *Handler) UpdateUserHandler(c *gin.Context) {
	id := c.Param("id")

	// Привязываем данные запроса к структуре UpdateUserRequest
	var input UpdateUserRequest

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	// Преобразуем данные в структуру dto.UpdateUserData
	data := dto.UpdateUserData{
		Username:          input.Username,
		Email:             input.Email,
		Phone:             input.Phone,
		Role:              input.Role,
		Status:            input.Status,
		PasswordUpdatedAt: input.PasswordUpdatedAt,
		CreatedAt:         input.CreatedAt,
		LastLogin:         input.LastLogin,
	}

	// Если телефон не nil, шифруем и добавляем в структуру данных
	if input.Phone != nil {
		encryptedPhone, err := security.EncryptPhoneNumber(*input.Phone, config.PhoneSecretKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encrypt phone"})
			return
		}
		data.Phone = &encryptedPhone // Передаем зашифрованный телефон
	}

	// Передаем ID и данные в метод репозитория
	err := h.userRepo.UpdateUser(id, data) // input.Username, input.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User updated"})
}

// DeleteUserHandler удаляет пользователя.
// @Summary Удаление пользователя
// @Description Удаляет пользователя по ID. Требуется авторизация через Bearer Token.
// @Tags users
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer токен" example("Bearer your_token")
// @Param id path string true "ID пользователя"
// @Success 200 {object} MessageResponse{message=string}
// @Failure 500 {object} ErrorResponse "Ошибка удаления пользователя"
// @Security BearerAuth
// @Router /api/auth/admin/users/{id} [delete]
func (h *Handler) DeleteUserHandler(c *gin.Context) {
	id := c.Param("id")
	err := h.userRepo.DeleteUser(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User deleted"})
}

// UpdateUserStatusHandler обновляет статус пользователя.
// @Summary Обновление данных пользователя
// @Description Обновляет статус пользователя. Требуется авторизация через Bearer Token.
// @Tags users
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer токен" example("Bearer your_token")
// @Param id path string true "ID пользователя"
// @Param input body UpdateUserStatusRequest true "Данные для обновления статуса пользователя"
// @Success 200 {object} MessageResponse{message=string}
// @Failure 400 {object} ErrorResponse "Некорректные данные запроса"
// @Failure 500 {object} ErrorResponse "Ошибка обновления пользователя"
// @Security BearerAuth
// @Router /api/auth/admin/users/{id}/status [put]
func (h *Handler) UpdateUserStatusHandler(c *gin.Context) {
	id := c.Param("id")

	// Привязываем данные запроса к структуре UpdateUserRequest
	var input UpdateUserStatusRequest

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	// Преобразуем данные в структуру dto.UpdateUserData
	data := dto.UpdateUserStatus{
		Status: input.Status,
	}

	status := *data.Status
	// Передаем ID и данные в метод репозитория
	err := h.userRepo.UpdateStatus(id, status) // input.Username, input.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User status updated"})
}

// UpdateUserRoleHandler обновляет роль пользователя.
// @Summary Обновление данных пользователя
// @Description Обновляет статус пользователя. Требуется авторизация через Bearer Token.
// @Tags users
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer токен" example("Bearer your_token")
// @Param id path string true "ID пользователя"
// @Param input body UpdateUserRoleRequest true "Данные для обновления роли пользователя"
// @Success 200 {object} MessageResponse{message=string}
// @Failure 400 {object} ErrorResponse "Некорректные данные запроса"
// @Failure 500 {object} ErrorResponse "Ошибка обновления пользователя"
// @Security BearerAuth
// @Router /api/auth/admin/users/{id}/assign-role [put]
func (h *Handler) UpdateUserRoleHandler(c *gin.Context) {

	id := c.Param("id")
	currentRole := c.GetString("role")

	exists, err := h.userRepo.ExistsById(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
		return
	}
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Failed to update user"})
		return
	}

	var input UpdateUserRoleRequest

	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	data := dto.UpdateUserRole{
		Role: input.Role,
	}

	role := *data.Role

	currentRoleIndex := middleware.RoleIndex(currentRole)
	newRoleIndex := middleware.RoleIndex(role)

	// Запрещаем пользователю менять свою роль
	if newRoleIndex >= currentRoleIndex {
		c.JSON(http.StatusForbidden, gin.H{"error": "You cannot change this role"})
		return
	}

	// Проверяем, является ли роль валидной
	if !middleware.Contains(middleware.ValidRoles, role) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid role"})
		return
	}

	// Передаем ID и роль в метод репозитория
	err = h.userRepo.UpdateUserRole(id, role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Role updated successfully"})
}
