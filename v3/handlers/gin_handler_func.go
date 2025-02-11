package handlers

import (
	"apiP/v3/config"
	"apiP/v3/db_postgres"
	"apiP/v3/middleware"
	"apiP/v3/security"
	"apiP/v3/validation"
	"database/sql"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"log"
	"log/slog"
	"net/http"
	"strconv"
)

// RegisterByEmailHandler обработчик для документации по упрощённой регистрации.
//
// @Summary Упрощённая регистрация нового пользователя
// @Description Регистрирует нового пользователя, указывая только почта и пароль.
// @Tags auth
// @Accept json
// @Produce json
// @Param user body RegisterRequestEmail true "Данные пользователя для упрощённой регистрации"
// @Success 200 {object} map[string]string "message: Регистрация прошла успешно"
// @Failure 400 {object} map[string]string "error: Неверные данные запроса"
// @Failure 500 {object} map[string]string "error: Ошибка при регистрации пользователя"
// @Router /api/auth/register/emile [post]
func RegisterByEmailHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var user RegisterRequestEmail

		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Неверные данные запроса"})
			return
		}

		// Валидация обязательных полей
		if err := validation.ValidatePassword(user.Password); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный почта или пароль"})
			return
		}

		if err := validation.ValidateEmail(user.Email); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный почта или пароль"})
			return
		}

		if err := db_postgres.CheckEmailUniqueness(db, user.Email); err != nil {
			c.JSON(http.StatusConflict, gin.H{"error": "Такой почта уже существует"})
			return
		}

		// Хэширование пароля
		passwordHash, err := bcrypt.GenerateFromPassword([]byte(*user.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// ID нового пользователя
		var userID *uuid.UUID

		// Попытка добавить пользователя в базу
		if userID, err = db_postgres.InsertUser(db, userID, nil, user.Email, nil, passwordHash); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при регистрации пользователя"})
			return
		}

		slog.Info("Пользователь успешно зарегистрирован", slog.String("userid", userID.String()))
		c.JSON(http.StatusOK, gin.H{"message": "Регистрация прошла успешно"})
	}
}

// RegisterByPhoneHandler обработчик для документации по упрощённой регистрации.
//
// @Summary Упрощённая регистрация нового пользователя
// @Description Регистрирует нового пользователя, указывая только телефон и пароль.
// @Tags auth
// @Accept json
// @Produce json
// @Param user body RegisterByPhoneRequest true "Данные пользователя для упрощённой регистрации"
// @Success 200 {object} map[string]string "message: Регистрация прошла успешно"
// @Failure 400 {object} map[string]string "error: Неверные данные запроса"
// @Failure 500 {object} map[string]string "error: Ошибка при регистрации пользователя"
// @Router /api/auth/register/phone [post]
func RegisterByPhoneHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var user RegisterByPhoneRequest

		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Неверные данные запроса"})
			return
		}

		// Валидация обязательных полей
		if err := validation.ValidatePassword(user.Password); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный телефон или пароль"})
			return
		}
		if err := validation.ValidatePhone(user.Phone); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Неверный телефон или пароль"})
			return
		}

		var phone string
		var err error
		key := config.PhoneSecretKey // os.Getenv("PHONE_SECRET_KEY")
		if user.Phone != nil {
			if *user.Phone == "" {
				user.Phone = nil
			} else {
				phone, err = security.EncryptPhoneNumber(*user.Phone, key)
				user.Phone = &phone
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при шифровании телефона"})
					return
				}
			}
		}

		// Проверка уникальности
		if err := db_postgres.CheckPhoneUniqueness(db, user.Phone); err != nil {
			c.JSON(http.StatusConflict, gin.H{"error": "Такой телефон уже занят"}) // c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
			return
		}

		// Хэширование пароля
		passwordHash, err := bcrypt.GenerateFromPassword([]byte(*user.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// ID нового пользователя
		var userID *uuid.UUID

		// Попытка добавить пользователя в базу
		if userID, err = db_postgres.InsertUser(db, userID, nil, nil, user.Phone, passwordHash); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при регистрации пользователя"})
			return
		}

		slog.Info("Пользователь успешно зарегистрирован", slog.String("userid", userID.String()))
		c.JSON(http.StatusOK, gin.H{"message": "Регистрация прошла успешно"})
	}
}

// RegisterHandlerDB обработчик для регистрации пользователя.
//
// @Summary Регистрация нового пользователя
// @Description Регистрирует нового пользователя с уникальным email, username или phone. Обязательные поля определяются конфигурацией.
// @Tags auth
// @Accept json
// @Produce json
// @Param user body RegisterRequest true "Данные пользователя для регистрации"
// @Success 200 {object} map[string]string "message: Регистрация прошла успешно"
// @Failure 400 {object} map[string]string "error: Неверные данные запроса"
// @Failure 409 {object} map[string]string "error: Имя пользователя/электронная почта/номер телефона уже используются"
// @Failure 500 {object} map[string]string "error: Ошибка при создании хэша пароля или записи в базу данных"
// @Router /api/auth/register [post]
func RegisterHandlerDB(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var user RegisterRequest

		if err := c.BindJSON(&user); err != nil {
			slog.Warn("Некорректный запрос на регистрацию", slog.Any("err", err))
			c.JSON(http.StatusBadRequest, gin.H{"error": "Некорректные данные запроса"})
			return
		}

		// Валидация обязательных полей
		currentFields := config.GetRequiredFields()
		if err := validateFields(&user, currentFields); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Проверка уникальности пользователя
		if err := checkUniqueness(db, user); err != nil {
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
			return
		}

		// Хэшируем пароль
		passwordHash, err := bcrypt.GenerateFromPassword([]byte(*user.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при создании хэша пароля"})
			return
		}

		if user.Username != nil {
			if *user.Username == "" {
				user.Username = nil
			}
		}

		var phone string
		key := config.PhoneSecretKey // os.Getenv("PHONE_SECRET_KEY")
		if user.Phone != nil {
			if *user.Phone == "" {
				user.Phone = nil
			} else {
				phone, err = security.EncryptPhoneNumber(*user.Phone, key)
				user.Phone = &phone
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при шифровании телефона"})
					return
				}
			}
		}

		if user.Email != nil {
			if *user.Email == "" {
				user.Email = nil
			}
		}

		// ID нового пользователя
		var userID *uuid.UUID

		// Попытка добавить пользователя в базу
		if userID, err = db_postgres.InsertUser(db, userID, user.Username, user.Email, user.Phone, passwordHash); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при регистрации пользователя"})
			return
		}
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при регистрации пользователя"})
			return
		}

		slog.Info("Пользователь успешно зарегистрирован", slog.String("userid", userID.String()))
		c.JSON(http.StatusOK, gin.H{"message": "Регистрация прошла успешно"})
	}
}

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

// DeleteUserHandler Удаление пользователя по ID
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

// AssignRoleHandler Изменение роли по username, email, phone
func AssignRoleHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		currentRole := c.GetString("role")

		var req struct {
			Identifier string `json:"identifier"`
			Role       string `json:"role"`
		}

		var err error

		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
			return
		}
		identifier := req.Identifier
		// Определяем поле для поиска
		var field string
		if validation.EmailRegex.MatchString(identifier) {
			field = "email"
		} else if validation.PhoneRegex.MatchString(identifier) {
			field = "phone"
		} else if validation.UsernameRegex.MatchString(identifier) {
			field = "username"
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
			return
		}
		log.Println(field, req.Identifier)
		if field == "phone" {
			key := config.PhoneSecretKey
			identifier, err = security.EncryptPhoneNumber(identifier, key)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при шифровании телефона"})
				return
			}
		}

		var userExists bool
		err = db.QueryRow(fmt.Sprintf("SELECT EXISTS (SELECT 1 FROM users WHERE %s = $1)", field), identifier).Scan(&userExists)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
			return
		}
		if !userExists {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}

		currentRoleIndex := middleware.RoleIndex(currentRole)
		newRoleIndex := middleware.RoleIndex(req.Role)

		if newRoleIndex >= currentRoleIndex {
			c.JSON(http.StatusForbidden, gin.H{"error": "You cannot change your own role"})
			return
		}

		if !middleware.Contains(middleware.ValidRoles, req.Role) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid role"})
			return
		}

		log.Println("Updating role for", field, "=", identifier, "to", req.Role)
		_, err = db.Exec(fmt.Sprintf("UPDATE users SET role = $1 WHERE %s = $2", field), req.Role, identifier)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update role"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Role updated successfully"})
	}
}
