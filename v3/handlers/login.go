// v3/handlers/login.go
package handlers

import (
	"apiP/v3/config"
	"apiP/v3/middleware"
	"apiP/v3/security"
	"apiP/v3/validation"
	"fmt"
	"github.com/didip/tollbooth"
	"github.com/didip/tollbooth_gin"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"

	"net/http"
	"time"
)

const passwordExpirationDays = 90 // Период действия пароля в днях

func isPasswordExpired(passwordUpdatedAt time.Time) bool {
	//log.Println("DB Value:", passwordUpdatedAt)
	//log.Println("Now (UTC):", time.Now().UTC())

	// Проверяем, истёк ли срок действия пароля
	return time.Since(passwordUpdatedAt) > (time.Hour * 24 * passwordExpirationDays)
}

func GetLoginFieldsHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, config.GetPossibleFields())
	}
}

func SupportedLoginFieldsHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Пример: возврат поддерживаемых полей
		c.JSON(http.StatusOK, gin.H{
			"fields": []string{"username", "email", "phone"},
		})
	}
}

func determineLoginField(user *LoginRequest, possibleFields []string) (string, string, error) {

	for _, field := range possibleFields {
		var value string
		switch field {
		case "username":
			if user.Username != nil {
				if *user.Username != "" {
					value = *user.Username
				}
			}
		case "email":
			if user.Email != nil {
				if *user.Email != "" {
					if !validation.EmailRegex.MatchString(*user.Email) {
						return "", "", fmt.Errorf("invalid email address")
					}
					value = *user.Email
				}
			}
		case "phone":
			if user.Phone != nil {
				if *user.Phone != "" {
					if !validation.PhoneRegex.MatchString(*user.Phone) {
						return "", "", fmt.Errorf("invalid phone number")
					}
					value = *user.Phone
				}
			}
		default:
			continue
		}

		if value != "" {
			return field, value, nil
		}
	}

	return "", "", fmt.Errorf("no valid login field provided")
}

// LoginHandler авторизует пользователя с помощью логина и пароля, возвращая токен доступа.
//
// @Summary Авторизация пользователя
// @Description Авторизация с использованием логина и пароля. Возвращает JWT токен доступа и устанавливает refresh токен в Cookie.
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body handlers.LoginRequest true "Данные для авторизации"
// @Success 200 {object} map[string]string "Успешный ответ с токеном доступа"
// @Failure 400 {object} map[string]string "Ошибка данных запроса"
// @Failure 401 {object} map[string]string "Неверные учетные данные"
// @Failure 403 {object} map[string]string "Срок действия пароля истёк"
// @Failure 429 {object} map[string]string "Слишком много запросов"
// @Failure 500 {object} map[string]string "Ошибка сервера"
// @Header 200 {string} Authorization "Bearer <токен доступа>"
// @Router /api/auth/login [post]
func (h *Handler) LoginHandler(c *gin.Context) {
	//func LoginHandler(userRepo repository.UserRepository) gin.HandlerFunc {
	// Настраиваем лимитер для ограничения запросов
	limiter := tollbooth.NewLimiter(5, nil) // Максимум 5 запросов в минуту
	limiter.SetMessage("Слишком много запросов, попробуйте позже.")
	limiter.SetMessageContentType("application/json")

	// Применяем rate limiting
	tollbooth_gin.LimitHandler(limiter)(c)
	if c.IsAborted() {
		return
	}

	// Читаем данные запроса
	var user LoginRequest
	if err := c.BindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Ошибка данных запроса"})
		return
	}

	if err := validation.ValidatePassword(user.Password); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Пароль слишком короткий"})
		return
	}

	// Получаем список допустимых полей для логина
	possibleFields := config.GetPossibleFields()
	if len(possibleFields) == 0 {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка конфигурации сервера"})
		return
	}

	field, value, err := determineLoginField(&user, possibleFields)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Неверные данные для входа"})
		return
	}

	if field == "phone" {
		key := config.PhoneSecretKey
		value, err = security.EncryptPhoneNumber(value, key)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при шифровании телефона"})
			return
		}
	}

	// Получаем пользователя из репозитория
	userID, storedHash, storedRole, passwordUpdatedAt, err := h.userRepo.FetchUser(field, value)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Неверные учетные данные"})
		return
	}

	// Проверяем пароль
	err = bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(*user.Password))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Неверные учетные данные"})
		return
	}

	// Проверяем срок действия пароля
	if isPasswordExpired(passwordUpdatedAt) {
		c.JSON(http.StatusForbidden, gin.H{"error": "Срок действия пароля истёк. Пожалуйста, смените пароль."})
		return
	}

	// Генерация JWT
	token, err := middleware.GenerateJWT(userID, storedRole)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при генерации токена"})
		return
	}

	refreshToken, err := middleware.GenerateRefreshToken(userID, storedRole)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при генерации токена"})
		return
	}

	now := time.Now()
	if err := h.userRepo.UpdateLastLogin(userID, now); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при обновлении времени последнего входа"})
		return
	}

	// Настройка Cookie для Refresh токена
	isSecure := config.Environment == "production"
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "refreshToken",
		Value:    refreshToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   isSecure,
		SameSite: http.SameSiteLaxMode,
	})

	c.Header("Authorization", fmt.Sprintf("Bearer %s", token))
	c.JSON(http.StatusOK, gin.H{"message": "Login successful"})
}

// рабочая функция

//// LoginHandlerDB авторизует пользователя с помощью логина, пароля и возвращает токен доступа.
////
//// @Summary Авторизация пользователя
//// @Description Авторизация с использованием логина и пароля. Возвращает JWT токен доступа и устанавливает refresh токен в Cookie.
//// @Tags Authentication
//// @Accept json
//// @Produce json
//// @Param request body handlers.LoginRequest true "Данные для авторизации"
//// @Success 200 {object} map[string]string "Успешный ответ с токеном доступа"
//// @Failure 400 {object} map[string]string "Ошибка данных запроса"
//// @Failure 401 {object} map[string]string "Неверные учетные данные"
//// @Failure 403 {object} map[string]string "Срок действия пароля истёк"
//// @Failure 429 {object} map[string]string "Слишком много запросов"
//// @Failure 500 {object} map[string]string "Ошибка сервера"
//// @Header 200 {string} Authorization "Bearer <токен доступа>"
//// @Router /api/auth/login [post]
//func LoginHandlerDB(db *sql.DB) gin.HandlerFunc {
//	// Настраиваем лимитер для ограничения запросов
//	limiter := tollbooth.NewLimiter(5, nil) // Максимум 5 запросов в минуту
//	limiter.SetMessage("Слишком много запросов, попробуйте позже.")
//	limiter.SetMessageContentType("application/json")
//
//	return func(c *gin.Context) {
//		// Применяем rate limiting
//		tollbooth_gin.LimitHandler(limiter)(c)
//		if c.IsAborted() {
//			return
//		}
//
//		// Читаем данные запроса
//		var user LoginRequest
//		if err := c.BindJSON(&user); err != nil {
//			slog.Error("Ошибка данных запроса", slog.Any("err", err))
//			c.JSON(http.StatusBadRequest, gin.H{"error": "Ошибка данных запроса"})
//			return
//		}
//		//log.Printf("Полученные данные JSON: %+v", user) // Логируем данные после успешного парсинга
//
//		if err := validation.ValidatePassword(user.Password); err != nil {
//			slog.Warn("Пароль слишком короткий", slog.Any("password_length", err))
//			c.JSON(http.StatusBadRequest, gin.H{"error": "Пароль слишком короткий"})
//			return
//		}
//
//		// Получаем список допустимых полей для логина
//		possibleFields := config.GetPossibleFields()
//		if len(possibleFields) == 0 {
//			slog.Error("Ошибка конфигурации сервера")
//			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка конфигурации сервера"})
//			return
//		}
//
//		field, value, err := determineLoginField(&user, possibleFields)
//		if err != nil {
//			slog.Warn("Неверные данные для входа", slog.Any("err", err))
//			c.JSON(http.StatusUnauthorized, gin.H{"error": "Неверные данные для входа"})
//			return
//		}
//
//		if field == "phone" {
//			key := config.PhoneSecretKey // os.Getenv("PHONE_SECRET_KEY")
//
//			value, err = security.EncryptPhoneNumber(value, key)
//
//			if err != nil {
//				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при шифровании телефона"})
//				return
//			}
//		}
//
//		userID, storedHash, storedRole, passwordUpdatedAt, err := db_postgres.FetchUserFromDB(db, field, value)
//		if err != nil {
//			slog.Warn("Неверные учетные данные", slog.Any("err", err))
//			c.JSON(http.StatusUnauthorized, gin.H{"error": "Неверные учетные данные"})
//			return
//		}
//
//		// Проверяем пароль
//		err = bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(*user.Password))
//		if err != nil {
//			slog.Warn("Неверные учетные данные", slog.Any("err", err))
//			c.JSON(http.StatusUnauthorized, gin.H{"error": "Неверные учетные данные"})
//			return
//		}
//
//		// Проверяем срок действия пароля
//		if isPasswordExpired(passwordUpdatedAt) {
//			slog.Warn("Срок действия пароля истёк", slog.String("userID", userID))
//			c.JSON(http.StatusForbidden, gin.H{"error": "Срок действия пароля истёк. Пожалуйста, смените пароль."})
//			return
//		}
//
//		// Генерация JWT
//		token, err := middleware.GenerateJWT(userID, storedRole) // userID.String()
//		if err != nil {
//			slog.Error("Ошибка при генерации токена", slog.String("userID", userID), slog.Any("err", err))
//			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при генерации токена"})
//			return
//		}
//
//		refreshToken, err := middleware.GenerateRefreshToken(userID, storedRole) // userID.String()
//		if err != nil {
//			slog.Error("Ошибка при генерации токена", slog.String("userID", userID), slog.Any("err", err))
//			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при генерации токена"})
//			return
//		}
//
//		// Настройка Cookie для Refresh токена
//		isSecure := config.Environment == "production"
//		http.SetCookie(c.Writer, &http.Cookie{
//			Name:     "refreshToken",
//			Value:    refreshToken,
//			Path:     "/",
//			HttpOnly: true,
//			Secure:   isSecure,
//			SameSite: http.SameSiteLaxMode,
//		})
//
//		slog.Info("Авторизация успешна", slog.String("userID", userID))
//		// Отправляем ответ клиенту
//		c.Header("Authorization", fmt.Sprintf("Bearer %s", token))
//		c.JSON(http.StatusOK, gin.H{"message": "Login successful"})
//	}
//}

//////////////////////

//func fetchUserFromDB(db *sql.DB, field, value string) (string, string, string, time.Time, error) {
//	var storedHash, storedRole string
//	var passwordUpdatedAt time.Time
//	var userID uuid.UUID
//
//	query := fmt.Sprintf("SELECT id, password, role, password_updated_at FROM users WHERE %s = $1", pq.QuoteIdentifier(field))
//	err := db.QueryRow(query, value).Scan(&userID, &storedHash, &storedRole, &passwordUpdatedAt)
//	if err != nil {
//		if err == sql.ErrNoRows {
//			return "", "", "", time.Time{}, fmt.Errorf("no user found for the provided field")
//		}
//		return "", "", "", time.Time{}, fmt.Errorf("database error: %w", err)
//	}
//
//	return userID.String(), storedHash, storedRole, passwordUpdatedAt, nil
//}

///////////////////////////////////////////////////

//// Функция для фильтрации пустых полей
//func filterEmptyFields(user LoginRequest) LoginRequest {
//	if user.Username != nil && *user.Username == "" {
//		user.Username = nil
//	}
//	if user.Password != nil && *user.Password == "" {
//		user.Password = nil
//	}
//	if user.Email != nil && *user.Email == "" {
//		user.Email = nil
//	}
//	if user.Phone != nil && *user.Phone == "" {
//		user.Phone = nil
//	}
//	return user
//}

//// Вспомогательная функция для получения значения указанного поля
//func getFieldValue(user LoginRequest, field string) string {
//	switch field {
//	case "username":
//		return *user.Username
//	case "email":
//		return *user.Email
//	case "phone":
//		return *user.Phone
//	default:
//		return ""
//	}
//}

//func LoginHandlerDB(db *sql.DB) gin.HandlerFunc {
//	// Настраиваем лимитер
//	limiter := tollbooth.NewLimiter(5, nil) // Максимум 5 запросов в минуту
//	limiter.SetMessage("Слишком много запросов, попробуйте позже.")
//	limiter.SetMessageContentType("application/json")
//
//	return func(c *gin.Context) {
//		// Применяем rate limiting
//		tollbooth_gin.LimitHandler(limiter)(c)
//		if c.IsAborted() {
//			return
//		}
//
//		// Читаем данные запроса
//		var user LoginRequest
//		if err := c.BindJSON(&user); err != nil {
//			handleError(c, err, "Ошибка данных запроса", http.StatusBadRequest)
//			return
//		}
//
//		// Валидация данных
//		if user.Username == "" || len(user.Username) < 3 {
//			// "Имя пользователя должно содержать не менее 3 символов"
//			handleError(c, fmt.Errorf("username too short"), "Имя пользователя слишком короткое", http.StatusBadRequest)
//			return
//		}
//
//		if user.Password == "" || len(user.Password) < 6 {
//			// "Пароль должен содержать не менее 6 символов"
//			handleError(c, fmt.Errorf("password too short"), "Пароль слишком короткий", http.StatusBadRequest)
//
//			return
//		}
//
//		// Проверяем данные пользователя
//		var storedHash, storedRole string
//		var passwordUpdatedAt time.Time
//
//		err := db.QueryRow("SELECT password, role, password_updated_at FROM users WHERE username = $1", user.Username).Scan(&storedHash, &storedRole, &passwordUpdatedAt)
//		if err == sql.ErrNoRows {
//			//c.JSON(http.StatusUnauthorized, gin.H{"error": "Неверные учетные данные"})
//			handleError(c, err, "Неверные учетные данные", http.StatusUnauthorized)
//			return
//		} else if err != nil {
//			//c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка сервера"})
//			handleError(c, err, "Ошибка при обработке данных", http.StatusInternalServerError)
//			return
//		}
//
//		// Проверяем пароль
//		err = bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(user.Password))
//		if err != nil {
//			//c.JSON(http.StatusUnauthorized, gin.H{"error": "Неверные учетные данные"})
//			handleError(c, err, "Неверные учетные данные", http.StatusUnauthorized)
//			return
//		}
//
//		// Проверяем срок действия пароля
//		if isPasswordExpired(passwordUpdatedAt) {
//			handleError(c, fmt.Errorf("password expired"), "Срок действия пароля истёк. Пожалуйста, смените пароль.", http.StatusForbidden)
//			return
//		}
//
//		// Генерация JWT
//		var userID uuid.UUID
//		err = db.QueryRow("SELECT id FROM users WHERE username = $1", user.Username).Scan(&userID)
//		if err != nil {
//			if err == sql.ErrNoRows {
//				// Пользователь не найден
//				handleError(c, err, "Неверные учетные данные", http.StatusUnauthorized)
//			} else {
//				// Другие ошибки БД
//				handleError(c, err, "Ошибка при авторизации", http.StatusInternalServerError)
//			}
//			return
//		}
//
//		token, err := middleware.GenerateJWT(userID.String(), storedRole)
//		if err != nil {
//			//c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при генерации токена"})
//			handleError(c, err, "Ошибка при генерации токена", http.StatusInternalServerError)
//			return
//		}
//
//		// Генерация refresh токена
//		refreshToken, err := middleware.GenerateRefreshToken(userID.String(), storedRole)
//		if err != nil {
//			//c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при создании refresh токена"})
//			handleError(c, err, "Ошибка при генерации токена", http.StatusInternalServerError)
//			return
//		}
//
//		// Настройка cookie Secure в зависимости от окружения
//		isSecure := config.Environment == "production"
//
//		http.SetCookie(c.Writer, &http.Cookie{
//			Name:     "refreshToken",
//			Value:    refreshToken,
//			Path:     "/",
//			HttpOnly: true,
//			Secure:   isSecure, // Secure включается только в production
//			SameSite: http.SameSiteLaxMode,
//		})
//
//		// Добавляем токены в заголовок
//		c.Header("Authorization", fmt.Sprintf("Bearer %s", token))
//		c.JSON(http.StatusOK, gin.H{"message": "Login successful"})
//	}
//}

/////////

//func LoginHandlerDB(db *sql.DB) gin.HandlerFunc {
//	// Настраиваем лимитер
//	limiter := tollbooth.NewLimiter(5, nil) // Максимум 5 запросов в минуту
//	limiter.SetMessage("Слишком много запросов, попробуйте позже.")
//	limiter.SetMessageContentType("application/json")
//
//	return func(c *gin.Context) {
//		// Применяем лимитер
//		tollbooth_gin.LimitHandler(limiter)(c)
//		if c.IsAborted() {
//			return
//		}
//
//		// Читаем данные запроса
//		var user LoginRequest
//		if err := c.BindJSON(&user); err != nil {
//			c.JSON(http.StatusBadRequest, gin.H{"error": "Неверные данные запроса"})
//			return
//		}
//
//		// Валидация входных данных
//		if user.Username == "" || len(user.Username) < 3 {
//			c.JSON(http.StatusBadRequest, gin.H{"error": "Имя пользователя должно содержать не менее 3 символов"})
//			return
//		}
//
//		if user.Password == "" || len(user.Password) < 6 {
//			c.JSON(http.StatusBadRequest, gin.H{"error": "Пароль должен содержать не менее 6 символов"})
//			return
//		}
//
//		// Получаем хэш пароля и роль пользователя из базы данных
//		var storedHash, storedRole string
//		err := db.QueryRow("SELECT password, role FROM users WHERE username = $1", user.Username).Scan(&storedHash, &storedRole)
//		if err == sql.ErrNoRows {
//			c.JSON(http.StatusUnauthorized, gin.H{"error": "Неверные учетные данные"})
//			return
//		} else if err != nil {
//			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка базы данных"})
//			return
//		}
//
//		// Проверяем соответствие введенного пароля хэшу
//		err = bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(user.Password))
//		if err != nil {
//			c.JSON(http.StatusUnauthorized, gin.H{"error": "Неверные учетные данные"})
//			return
//		}
//
//		// получаем ID
//		var userID uuid.UUID
//		err = db.QueryRow(
//			"SELECT id FROM users WHERE username = $1",
//			user.Username).Scan(&userID)
//		if err != nil {
//			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка получения ID пользователя: " + err.Error()})
//			return
//		}
//
//		// Генерация JWT токена
//		token, err := middleware.GenerateJWT(userID.String(), storedRole) // fmt.Sprintf("%d", userID)
//		if err != nil {
//			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при генерации токена"})
//			return
//		}
//
//		//// Удаляем старый refresh токен
//		//_, err = db.Exec("DELETE FROM refresh_tokens WHERE username = $1", user.Username)
//		//if err != nil {
//		//	c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при удалении старого refresh токена"})
//		//	return
//		//}
//
//		// Генерация нового refresh токена
//		refreshToken, err := middleware.GenerateRefreshToken(userID.String(), storedRole)
//		if err != nil {
//			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при генерации refresh токена"})
//			return
//		}
//
//		//// Сохраняем refresh токен в базе данных
//		//_, err = db.Exec("INSERT INTO refresh_tokens (username, token) VALUES ($1, $2)", user.Username, refreshToken)
//		//if err != nil {
//		//	c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при сохранении refresh токена"})
//		//	return
//		//}
//
//		//// Возвращаем токен доступа и refresh токен
//		//c.JSON(http.StatusOK, gin.H{
//		//	"token":        token,
//		//	"refreshToken": refreshToken,
//		//})
//
//		// Устанавливаем refreshToken как HttpOnly cookie
//		http.SetCookie(c.Writer, &http.Cookie{
//			Name:     "refreshToken",
//			Value:    refreshToken,
//			Path:     "/",
//			HttpOnly: true,
//			Secure:   false, // Для локальной разработки
//			SameSite: http.SameSiteLaxMode,
//		})
//
//		// Удаляем сохранение в куки
//		// c.SetCookie("authToken", authToken, 3600, "/", "", true, true)
//		// c.SetCookie("refreshToken", refreshToken, 86400, "/", "", true, true)
//
//		// Добавляем токены в заголовки ответа
//		// c.Header("AuthToken", token)
//		c.Header("Authorization", fmt.Sprintf("Bearer %s", token))
//		//c.Header("RefreshToken", refreshToken)
//
//		c.JSON(http.StatusOK, gin.H{"message": "Login successful"})
//	}
//}

//func LoginHandlerDB(db *sql.DB) gin.HandlerFunc {
//	// Настраиваем лимитер
//	limiter := tollbooth.NewLimiter(5, nil) // Максимум 5 запросов в минуту
//	limiter.SetMessage("Слишком много запросов, попробуйте позже.")
//	limiter.SetMessageContentType("application/json")
//
//	return func(c *gin.Context) {
//		// Применяем rate limiting
//		tollbooth_gin.LimitHandler(limiter)(c)
//		if c.IsAborted() {
//			return
//		}
//
//		// Читаем данные запроса
//		var user LoginRequest
//		if err := c.BindJSON(&user); err != nil {
//			handleError(c, err, "Ошибка данных запроса", http.StatusBadRequest)
//			return
//		}
//
//		// Проверяем, что хотя бы один способ логина указан
//		if user.Username == "" && user.Email == "" && user.Phone == "" {
//			handleError(c, fmt.Errorf("no login field provided"), "Укажите имя пользователя, email или номер телефона", http.StatusBadRequest)
//			return
//		}
//
//		// Валидация данных
//		if user.Password == "" || len(user.Password) < 6 {
//			handleError(c, fmt.Errorf("password too short"), "Пароль слишком короткий", http.StatusBadRequest)
//			return
//		}
//
//		// Проверяем данные пользователя
//		var storedHash, storedRole string
//		var passwordUpdatedAt time.Time
//		var err error
//
//		// Приоритет проверки: username -> email -> phone
//		if user.Username != "" {
//			err = db.QueryRow("SELECT password, role, password_updated_at FROM users WHERE username = $1", user.Username).Scan(&storedHash, &storedRole, &passwordUpdatedAt)
//		} else if user.Email != "" {
//			err = db.QueryRow("SELECT password, role, password_updated_at FROM users WHERE email = $1", user.Email).Scan(&storedHash, &storedRole, &passwordUpdatedAt)
//		} else if user.Phone != "" {
//			err = db.QueryRow("SELECT password, role, password_updated_at FROM users WHERE phone = $1", user.Phone).Scan(&storedHash, &storedRole, &passwordUpdatedAt)
//		}
//
//		if err == sql.ErrNoRows {
//			handleError(c, err, "Неверные учетные данные", http.StatusUnauthorized)
//			return
//		} else if err != nil {
//			handleError(c, err, "Ошибка при обработке данных", http.StatusInternalServerError)
//			return
//		}
//
//		// Проверяем пароль
//		err = bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(user.Password))
//		if err != nil {
//			handleError(c, err, "Неверные учетные данные", http.StatusUnauthorized)
//			return
//		}
//
//		// Проверяем срок действия пароля
//		if isPasswordExpired(passwordUpdatedAt) {
//			handleError(c, fmt.Errorf("password expired"), "Срок действия пароля истёк. Пожалуйста, смените пароль.", http.StatusForbidden)
//			return
//		}
//
//		// Генерация JWT
//		var userID uuid.UUID
//		if user.Username != "" {
//			err = db.QueryRow("SELECT id FROM users WHERE username = $1", user.Username).Scan(&userID)
//		} else if user.Email != "" {
//			err = db.QueryRow("SELECT id FROM users WHERE email = $1", user.Email).Scan(&userID)
//		} else if user.Phone != "" {
//			err = db.QueryRow("SELECT id FROM users WHERE phone = $1", user.Phone).Scan(&userID)
//		}
//
//		if err != nil {
//			handleError(c, err, "Ошибка при авторизации", http.StatusInternalServerError)
//			return
//		}
//
//		token, err := middleware.GenerateJWT(userID.String(), storedRole)
//		if err != nil {
//			handleError(c, err, "Ошибка при генерации токена", http.StatusInternalServerError)
//			return
//		}
//
//		refreshToken, err := middleware.GenerateRefreshToken(userID.String(), storedRole)
//		if err != nil {
//			handleError(c, err, "Ошибка при генерации токена", http.StatusInternalServerError)
//			return
//		}
//
//		isSecure := config.Environment == "production"
//
//		http.SetCookie(c.Writer, &http.Cookie{
//			Name:     "refreshToken",
//			Value:    refreshToken,
//			Path:     "/",
//			HttpOnly: true,
//			Secure:   isSecure,
//			SameSite: http.SameSiteLaxMode,
//		})
//
//		c.Header("Authorization", fmt.Sprintf("Bearer %s", token))
//		c.JSON(http.StatusOK, gin.H{"message": "Login successful"})
//	}
//}
