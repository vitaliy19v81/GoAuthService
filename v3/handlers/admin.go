package handlers

import (
	"apiP/v3/config"
	"apiP/v3/dto"
	"apiP/v3/security"
	"database/sql"
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
	"strconv"
	"time"
)

//type UpdateUserRequest struct {
//	Username string `json:"username" example:"new_username"`
//	Role     string `json:"role" example:"admin"`
//}

type UpdateUserRequest struct {
	Username          *string `json:"username" example:"new_username"`
	Email             *string `json:"email" example:"new_email@example.com"`
	Phone             *string `json:"phone" example:"1234567890"`
	Role              *string `json:"role" example:"admin"`
	Status            *string `json:"status" example:"active"`
	PasswordUpdatedAt *string `json:"password_updated_at" example:"2024-12-25T15:04:05Z"`
	CreatedAt         *string `json:"created_at" example:"2024-12-01T12:00:00Z"`
	LastLogin         *string `json:"last_login" example:"2024-12-20T18:30:00Z"`
}

type SuccessResponse struct {
	Data         interface{} `json:"data"` // Используйте конкретный тип вместо `interface{}` (например, []User)
	TotalRecords int         `json:"totalRecords"`
	Limit        int         `json:"limit"`
	Offset       int         `json:"offset"`
}

type ErrorResponse struct {
	Error string `json:"error" example:"Описание ошибки"`
}

type MessageResponse struct {
	Message string `json:"message" example:"Операция выполнена успешно"`
}

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

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// рабочий код

// GetUsersHandlerDB Получение таблицы пользователей
// @Summary Получение списка пользователей
// @Description Возвращает список пользователей с информацией о роли, статусе и времени регистрации. Требуется авторизация через Bearer Token.
// @Tags users
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer токен" example("Bearer your_token")
// @Param length query int false "Количество записей для возврата (по умолчанию 10)"
// @Param start query int false "Смещение записей (по умолчанию 0)"
// @Success 200 {object} SuccessResponse
// @Failure 401 {object} ErrorResponse "Unauthorized"
// @Failure 500 {object} ErrorResponse "Ошибка при подсчёте общего числа записей"
// @Security BearerAuth
// @Router /api/auth/admin/users [get]
func GetUsersHandlerDB(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {

		// TODO усовершенствовать таблицу и решить проблему отображеничя в случаи возврата неверных данных

		//username := c.DefaultQuery("username", "")
		//role := c.DefaultQuery("role", "")
		//status := c.DefaultQuery("status", "")
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

		//// Подсчёт записей после фильтрации
		//var filteredRecords int
		//err = db.QueryRow(`
		//	SELECT COUNT(*)
		//	FROM users
		//	WHERE
		//        ($1 = '' OR username ILIKE $1) AND
		//        ($2 = '' OR role ILIKE $2) AND
		//        ($3 = '' OR status ILIKE $3)`,
		//	"%"+username+"%", "%"+role+"%", "%"+status+"%").Scan(&filteredRecords)
		//if err != nil {
		//	c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при подсчёте записей"})
		//	return
		//}

		// Подсчёт общего количества записей
		var totalRecords int
		err = db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&totalRecords)
		if err != nil {
			log.Println("Ошибка при подсчёте общего числа записей")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при подсчёте общего числа записей"})
			return
		}

		//query := `
		//	SELECT id, username, email, phone, role, status, password_updated_at, created_at, last_login
		//	FROM users
		//	WHERE
		//        ($1 = '' OR username ILIKE $1) AND
		//        ($2 = '' OR role ILIKE $2) AND
		//        ($3 = '' OR status ILIKE $3)
		//	LIMIT $4 OFFSET $5
		//`

		//rows, err := db.Query(query, "%"+username+"%", "%"+role+"%", "%"+status+"%", limit, offset)
		//if err != nil {
		//	c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при получении данных пользователей"})
		//	return
		//}
		//defer rows.Close()

		// Подготавливаем запрос для получения данных пользователей
		query := `
			SELECT id, username, email, phone, role, status, password_updated_at, created_at, last_login
			FROM users
			LIMIT $1 OFFSET $2
		`

		// Выполняем запрос
		rows, err := db.Query(query, limit, offset)
		if err != nil {
			log.Println("Ошибка при получении данных пользователей")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при получении данных пользователей"})
			return
		}
		defer rows.Close()

		var users []map[string]interface{}
		for rows.Next() {
			var user map[string]interface{}

			var id string
			var username, email, phone, role, status sql.NullString
			var passwordUpdatedAt, createdAt, lastLogin sql.NullTime

			err := rows.Scan(&id, &username, &email, &phone, &role, &status, &passwordUpdatedAt, &createdAt, &lastLogin)
			if err != nil {
				log.Println("Ошибка при чтении данных")
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при чтении данных"})
				return
			}

			user = map[string]interface{}{
				"id":                  id,
				"username":            nullStringToString(username),
				"email":               nullStringToString(email),
				"phone":               nullStringToString(phone),
				"role":                nullStringToString(role),
				"status":              nullStringToString(status),
				"password_updated_at": nullTimeToString(passwordUpdatedAt),
				"created_at":          nullTimeToString(createdAt),
				"last_login":          nullTimeToString(lastLogin),
			}

			// Расшифровка телефона
			if phone.Valid && phone.String != "" {
				key := config.PhoneSecretKey
				decryptedPhone, err := security.DecryptPhoneNumber(phone.String, key)
				if err != nil {
					log.Printf("Ошибка при расшифровке телефона: %v", err)
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при обработке телефона"})
					return
				}
				user["phone"] = decryptedPhone // Сохраняем расшифрованный телефон
			} else {
				user["phone"] = nullStringToString(phone) // На случай, если телефон пустой
			}

			users = append(users, user)
		}

		if err := rows.Err(); err != nil {
			log.Println("Ошибка обработки данных")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка обработки данных"})
			return
		}

		c.JSON(http.StatusOK, SuccessResponse{
			Data:         users,
			TotalRecords: totalRecords,
			Limit:        limit,
			Offset:       offset,
		})

		//c.JSON(http.StatusOK, gin.H{
		//	"data":         users,
		//	"totalRecords": totalRecords, // "recordsFiltered":filteredRecords,
		//	"limit":        limit,
		//	"offset":       offset,
		//})
	}
}

func nullStringToString(ns sql.NullString) string {
	if ns.Valid {
		return ns.String
	}
	return ""
}

func nullTimeToString(nt sql.NullTime) string {
	if nt.Valid {
		return nt.Time.Format(time.RFC3339) // Используйте формат времени ISO
	}
	return ""
}

func UpdateUserHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		var input struct {
			Username string `json:"username"`
			Role     string `json:"role"`
		}
		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
			return
		}

		_, err := db.Exec("UPDATE users SET username = $1, role = $2 WHERE id = $3", input.Username, input.Role, id)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "User updated"})
	}
}

func DeleteUserHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		log.Println(id)
		_, err := db.Exec("DELETE FROM users WHERE id = $1", id)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete user"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "User deleted"})
	}
}

//func GetUsersHandlerDB(db *sql.DB) gin.HandlerFunc {
//	return func(c *gin.Context) {
//		// Получаем параметры запроса
//		username := c.DefaultQuery("username", "")
//		role := c.DefaultQuery("role", "")
//		limitStr := c.DefaultQuery("limit", "10")  // Значение по умолчанию
//		offsetStr := c.DefaultQuery("offset", "0") // Значение по умолчанию
//
//		// Преобразуем limit и offset в числа
//		limit, err := strconv.Atoi(limitStr)
//		if err != nil || limit <= 0 {
//			limit = 10
//		}
//		offset, err := strconv.Atoi(offsetStr)
//		if err != nil || offset < 0 {
//			offset = 0
//		}
//
//		// Подсчёт общего количества записей
//		var totalRecords int
//		err = db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&totalRecords)
//		if err != nil {
//			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при подсчёте общего числа записей"})
//			return
//		}
//
//		// Подсчёт записей после фильтрации
//		var filteredRecords int
//		err = db.QueryRow(`
//			SELECT COUNT(*)
//			FROM users
//			WHERE username ILIKE $1 AND role ILIKE $2`,
//			"%"+username+"%", "%"+role+"%").Scan(&filteredRecords)
//		if err != nil {
//			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при подсчёте отфильтрованных записей"})
//			return
//		}
//
//		// Подготавливаем запрос
//		query := `
//			SELECT id, username, role, status, password_updated_at, created_at, last_login
//			FROM users
//			WHERE username ILIKE $1 AND role ILIKE $2
//			LIMIT $3 OFFSET $4
//		`
//
//		// Выполняем запрос
//		rows, err := db.Query(query, "%"+username+"%", "%"+role+"%", limit, offset)
//		if err != nil {
//			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при получении данных пользователей"})
//			return
//		}
//		defer rows.Close()
//
//		// Подготовка массива данных
//		var users []map[string]interface{}
//		for rows.Next() {
//			var id string
//			var username, role string
//			var passwordUpdatedAt time.Time
//
//			// Сканируем данные из БД
//			err := rows.Scan(&id, &username, &role, &passwordUpdatedAt)
//			if err != nil {
//				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при чтении данных пользователей"})
//				return
//			}
//
//			// Добавляем данные пользователя в массив
//			users = append(users, map[string]interface{}{
//				"id":                  id,
//				"username":            username,
//				"role":                role,
//				"password_updated_at": passwordUpdatedAt,
//			})
//		}
//
//		// Проверяем ошибки при итерации
//		if err := rows.Err(); err != nil {
//			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при обработке данных пользователей"})
//			return
//		}
//
//		// Возвращаем данные в формате JSON
//		c.JSON(http.StatusOK, gin.H{
//			"data": users,
//			//"recordsTotal":    totalRecords,
//			//"recordsFiltered": filteredRecords,
//			"limit":  limit,
//			"offset": offset,
//		})
//	}
//}

//////////

// Рабочий код без ленивой прокрутки
//func GetUsersHandlerDB(db *sql.DB) gin.HandlerFunc {
//	return func(c *gin.Context) {
//		// Получаем данные пользователей из БД
//		rows, err := db.Query("SELECT id, username, role, password_updated_at FROM users")
//		if err != nil {
//			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при получении данных пользователей"})
//			return
//		}
//		defer rows.Close()
//
//		// Подготовка массива данных
//		var users []map[string]interface{}
//		for rows.Next() {
//			var id string
//			var username, role string
//			var passwordUpdatedAt time.Time
//
//			// Сканируем данные из БД
//			err := rows.Scan(&id, &username, &role, &passwordUpdatedAt)
//			if err != nil {
//				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при чтении данных пользователей"})
//				return
//			}
//
//			// Добавляем данные пользователя в массив
//			users = append(users, map[string]interface{}{
//				"id":                  id,
//				"username":            username,
//				"role":                role,
//				"password_updated_at": passwordUpdatedAt,
//			})
//		}
//
//		// Проверяем ошибки при итерации
//		if err := rows.Err(); err != nil {
//			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при обработке данных пользователей"})
//			return
//		}
//
//		// Возвращаем данные в формате JSON
//		c.JSON(http.StatusOK, gin.H{
//			"data": users,
//		})
//	}
//}

//func GetUsersHandler(db *sql.DB) gin.HandlerFunc {
//	return func(c *gin.Context) {
//		// Проверка роли администратора
//		if c.GetString("role") != "admin" {
//			c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
//			return
//		}
//
//		rows, err := db.Query("SELECT id, username, role, password_updated_at FROM users")
//		if err != nil {
//			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch users"})
//			return
//		}
//		defer rows.Close()
//
//		var users []map[string]interface{}
//		for rows.Next() {
//			var id, username, role string
//			var passwordUpdatedAt string
//			if err := rows.Scan(&id, &username, &role, &passwordUpdatedAt); err != nil {
//				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse user"})
//				return
//			}
//			users = append(users, map[string]interface{}{
//				"id":                  id,
//				"username":            username,
//				"role":                role,
//				"password_updated_at": passwordUpdatedAt,
//			})
//		}
//
//		c.JSON(http.StatusOK, users)
//	}
//}
