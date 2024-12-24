// v3/handlers/register.go
package handlers

import (
	"apiP/v3/config"
	"database/sql"
	"fmt"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"time"
)

//// Регулярные выражения для email и phone
//var (
//	emailRegex = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)
//	phoneRegex = regexp.MustCompile(`^\+?\d{0,3}[-\s]?\(?\d{2,5}\)?[-\s]?\d{2,4}[-\s]?\d{2,4}[-\s]?\d{2,4}$`)
//)

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
// @Router /register [post]
func RegisterHandlerDB(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var user RegisterRequest

		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Неверные данные запроса"})
			return
		}

		// Проверка обязательных полей
		//fieldsMutex.RLock()
		//currentFields := requiredFields
		//fieldsMutex.RUnlock()

		// Валидация обязательных полей
		currentFields := config.GetRequiredFields()
		if err := validateFields(&user, currentFields); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		//currentFields := config.GetRequiredFields()
		//
		//for _, field := range currentFields {
		//	switch field {
		//	case "username":
		//		if user.Username == nil || len(*user.Username) < 3 {
		//			c.JSON(http.StatusBadRequest, gin.H{"error": "Username must be at least 3 characters long"})
		//			return
		//		}
		//	case "email":
		//		if user.Email == nil || !emailRegex.MatchString(*user.Email) {
		//			c.JSON(http.StatusBadRequest, gin.H{"error": "Email is required"})
		//			return
		//		}
		//	case "phone":
		//		if user.Phone == nil || !phoneRegex.MatchString(*user.Phone) {
		//			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid phone number"})
		//			return
		//		}
		//	case "password":
		//		if user.Password == nil || len(*user.Password) < 6 {
		//			c.JSON(http.StatusBadRequest, gin.H{"error": "Password must be at least 6 characters long"})
		//			return
		//		}
		//	default:
		//		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid field in required fields"})
		//		return
		//	}
		//}

		// Проверка уникальности пользователя
		if err := checkUniqueness(db, user); err != nil {
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
			return
		}

		//// Проверяем уникальность
		//var exists bool
		//var err error
		//
		//if user.Username != nil {
		//	err = db.QueryRow("SELECT EXISTS (SELECT 1 FROM users WHERE username = $1)", user.Username).Scan(&exists)
		//	if err == nil && exists {
		//		c.JSON(http.StatusConflict, gin.H{"error": "Имя пользователя уже занято"})
		//		return
		//	}
		//}
		//if user.Email != nil {
		//	err = db.QueryRow("SELECT EXISTS (SELECT 1 FROM users WHERE email = $1)", user.Email).Scan(&exists)
		//	if err == nil && exists {
		//		c.JSON(http.StatusConflict, gin.H{"error": "Электронная почта уже используется"})
		//		return
		//	}
		//}
		//if user.Phone != nil {
		//	err = db.QueryRow("SELECT EXISTS (SELECT 1 FROM users WHERE phone = $1)", user.Phone).Scan(&exists)
		//	if err == nil && exists {
		//		c.JSON(http.StatusConflict, gin.H{"error": "Номер телефона уже используется"})
		//		return
		//	}
		//}

		// Хэшируем пароль
		hash, err := bcrypt.GenerateFromPassword([]byte(*user.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при создании хэша пароля"})
			return
		}

		// Вставляем данные нового пользователя в базу
		_, err = db.Exec(
			`INSERT INTO users (username, password, email, phone, role, status, password_updated_at, created_at) 
             VALUES ($1, $2, $3, $4, 'user', 'active', $5, $6)`,
			user.Username, hash, user.Email, user.Phone, time.Now().UTC(), time.Now().UTC(),
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при регистрации пользователя"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Регистрация прошла успешно"})
	}
}

func validateFields(user *RegisterRequest, requiredFields []string) error {
	for _, field := range requiredFields {
		switch field {
		case "username":
			if user.Username == nil || len(*user.Username) < 3 {
				return fmt.Errorf("Username must be at least 3 characters long")
			}
		case "email":
			if user.Email == nil || !EmailRegex.MatchString(*user.Email) {
				return fmt.Errorf("Invalid email address")
			}
		case "phone":
			if user.Phone == nil || !PhoneRegex.MatchString(*user.Phone) {
				return fmt.Errorf("Invalid phone number")
			}
		case "password":
			if user.Password == nil || len(*user.Password) < 6 {
				return fmt.Errorf("Password must be at least 6 characters long")
			}
		default:
			return fmt.Errorf("Invalid field in required fields")
		}
	}
	return nil
}

// Проверка уникальности пользователя
func checkUniqueness(db *sql.DB, user RegisterRequest) error {
	var exists bool

	if user.Username != nil {
		err := db.QueryRow("SELECT EXISTS (SELECT 1 FROM users WHERE username = $1)", user.Username).Scan(&exists)
		if err == nil && exists {
			return fmt.Errorf("Имя пользователя уже занято")
		}
	}

	if user.Email != nil {
		err := db.QueryRow("SELECT EXISTS (SELECT 1 FROM users WHERE email = $1)", user.Email).Scan(&exists)
		if err == nil && exists {
			return fmt.Errorf("Электронная почта уже используется")
		}
	}

	if user.Phone != nil {
		err := db.QueryRow("SELECT EXISTS (SELECT 1 FROM users WHERE phone = $1)", user.Phone).Scan(&exists)
		if err == nil && exists {
			return fmt.Errorf("Номер телефона уже используется")
		}
	}

	return nil
}

//func RegisterHandlerDB(db *sql.DB) gin.HandlerFunc {
//	return func(c *gin.Context) {
//		//var user LoginRequest
//
//		var user RegisterRequest
//
//		if err := c.BindJSON(&user); err != nil {
//			c.JSON(http.StatusBadRequest, gin.H{"error": "Неверные данные запроса"})
//			return
//		}
//
//		//// Валидация входных данных
//		//if user.Username == "" || len(user.Username) < 3 {
//		//	c.JSON(http.StatusBadRequest, gin.H{"error": "Имя пользователя должно содержать не менее 3 символов"})
//		//	return
//		//}
//		//
//		//if user.Password == "" || len(user.Password) < 6 {
//		//	c.JSON(http.StatusBadRequest, gin.H{"error": "Пароль должен содержать не менее 6 символов"})
//		//	return
//		//}
//		//
//		//if user.Email == "" {
//		//	c.JSON(http.StatusBadRequest, gin.H{"error": "Email обязателен"})
//		//	return
//		//}
//		//
//		//// Проверяем, существует ли пользователь с таким же именем
//		//var exists bool
//		//err := db.QueryRow("SELECT EXISTS (SELECT 1 FROM users WHERE username = $1)", user.Username).Scan(&exists)
//		//if err != nil {
//		//	c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка базы данных"})
//		//	return
//		//}
//		//if exists {
//		//	c.JSON(http.StatusConflict, gin.H{"error": "Пользователь уже существует"})
//		//	return
//		//}
//
//		// Получаем текущий метод регистрации
//		method := config.GetRegistrationMethod()
//
//		var exists bool
//		var err error
//
//		switch method {
//		case "username":
//			if user.Username == "" || len(user.Username) < 3 {
//				c.JSON(http.StatusBadRequest, gin.H{"error": "Имя пользователя должно содержать не менее 3 символов"})
//				return
//			}
//			err = db.QueryRow("SELECT EXISTS (SELECT 1 FROM users WHERE username = $1)", user.Username).Scan(&exists)
//		case "email":
//			if user.Email == "" {
//				c.JSON(http.StatusBadRequest, gin.H{"error": "Электронная почта обязательна"})
//				return
//			}
//			err = db.QueryRow("SELECT EXISTS (SELECT 1 FROM users WHERE email = $1)", user.Email).Scan(&exists)
//		case "phone":
//			if user.Phone == "" || len(user.Phone) != 10 { // Пример: длина телефона — 10 цифр
//				c.JSON(http.StatusBadRequest, gin.H{"error": "Некорректный номер телефона"})
//				return
//			}
//			err = db.QueryRow("SELECT EXISTS (SELECT 1 FROM users WHERE phone = $1)", user.Phone).Scan(&exists)
//		default:
//			c.JSON(http.StatusBadRequest, gin.H{"error": "Недопустимый метод регистрации"})
//			return
//		}
//
//		// Хэшируем пароль
//		hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
//		if err != nil {
//			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при создании хэша пароля"})
//			return
//		}
//
//		// Вставляем данные нового пользователя в базу
//		_, err = db.Exec(
//			`INSERT INTO users (username, password, email, phone, role, status, password_updated_at, created_at)
//             VALUES ($1, $2, $3, $4, 'user', 'active', $5, $6)`,
//			user.Username, hash, user.Email, user.Phone, time.Now().UTC(), time.Now().UTC(),
//		)
//		if err != nil {
//			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при регистрации пользователя"})
//			return
//		}
//
//		c.JSON(http.StatusOK, gin.H{"message": "Регистрация прошла успешно"})
//	}
//}

//func RegisterHandlerDB(db *sql.DB) gin.HandlerFunc {
//	return func(c *gin.Context) {
//		// Читаем данные запроса
//		var user LoginRequest
//		if err := c.BindJSON(&user); err != nil {
//			c.JSON(http.StatusBadRequest, gin.H{"error": "Неверные данные запроса"})
//			return
//		}
//
//		// Проверяем, существует ли пользователь с таким именем
//		var exists bool
//		err := db.QueryRow("SELECT EXISTS (SELECT 1 FROM users WHERE username = $1)", user.Username).Scan(&exists)
//		if err != nil {
//			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка базы данных"})
//			return
//		}
//		if exists {
//			c.JSON(http.StatusConflict, gin.H{"error": "Пользователь уже существует"})
//			return
//		}
//
//		// Генерируем хэш пароля
//		hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
//		if err != nil {
//			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при создании хэша пароля"})
//			return
//		}
//
//		// Сохраняем пользователя в базе данных и получаем его ID
//		var userID uuid.UUID
//		err = db.QueryRow(
//			"INSERT INTO users (username, password, role) VALUES ($1, $2, $3) RETURNING id",
//			user.Username, hash, "user",
//		).Scan(&userID)
//		if err != nil {
//			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при регистрации пользователя: " + err.Error()})
//			return
//		}
//
//		// Генерация JWT токена с использованием ID
//		token, err := middleware.GenerateJWT(fmt.Sprintf("%d", userID), "user")
//		if err != nil {
//			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при генерации токена"})
//			return
//		}
//
//		// Генерация refresh токена с использованием ID
//		refreshToken, err := middleware.GenerateRefreshToken(fmt.Sprintf("%d", userID), "user")
//		if err != nil {
//			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при генерации refresh токена"})
//			return
//		}
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
//		// Установка токенов в заголовки
//		c.Header("Authorization", fmt.Sprintf("Bearer %s", token)) // Access токен
//		//c.Header("RefreshToken", refreshToken)                     // Refresh токен
//
//		// Возвращаем сообщение о регистрации
//		c.JSON(http.StatusOK, gin.H{
//			"message": "Регистрация прошла успешно",
//		})
//	}
//}

//func RegisterHandlerDB1(db *sql.DB) gin.HandlerFunc {
//	return func(c *gin.Context) {
//		// Читаем данные запроса
//		var user LoginRequest
//		if err := c.BindJSON(&user); err != nil {
//			c.JSON(http.StatusBadRequest, gin.H{"error": "Неверные данные запроса"})
//			return
//		}
//
//		// Проверяем, существует ли пользователь с таким именем
//		var exists bool
//		err := db.QueryRow("SELECT EXISTS (SELECT 1 FROM users WHERE username = $1)", user.Username).Scan(&exists)
//		if err != nil {
//			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка базы данных"})
//			return
//		}
//		if exists {
//			c.JSON(http.StatusConflict, gin.H{"error": "Пользователь уже существует"})
//			return
//		}
//
//		// Генерируем хэш пароля
//		hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
//		if err != nil {
//			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при создании хэша пароля"})
//			return
//		}
//
//		// Сохраняем пользователя с ролью "user" в базе данных
//		_, err = db.Exec("INSERT INTO users (username, password, role) VALUES ($1, $2, $3)", user.Username, hash, "user")
//		if err != nil {
//			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при регистрации пользователя"})
//			return
//		}
//
//		var userID int
//		err = db.QueryRow(
//			"INSERT INTO users (username, password, role) VALUES ($1, $2, $3) RETURNING id",
//			user.Username, hash, "user",
//		).Scan(&userID)
//		if err != nil {
//			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при регистрации пользователя"})
//			return
//		}
//
//		// Генерация JWT токена
//		token, err := middleware.GenerateJWT(user.Username, "user")
//		if err != nil {
//			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при генерации токена"})
//			return
//		}
//
//		// Генерация refresh токена
//		refreshToken, err := middleware.GenerateRefreshToken(user.Username, "user")
//		if err != nil {
//			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при генерации refresh токена"})
//			return
//		}
//
//		//c.Header("AuthToken", token)           // Access токен
//		c.Header("Authorization", fmt.Sprintf("Bearer %s", token))
//		c.Header("RefreshToken", refreshToken) // Refresh токен
//
//		// Возвращаем сообщение о регистрации
//		c.JSON(http.StatusOK, gin.H{
//			"message": "Регистрация прошла успешно",
//		})
//	}
//}
//
//func RegisterHandlerRefreshDB(db *sql.DB) gin.HandlerFunc {
//	return func(c *gin.Context) {
//		// Читаем данные запроса
//		var user LoginRequest
//		if err := c.BindJSON(&user); err != nil {
//			c.JSON(http.StatusBadRequest, gin.H{"error": "Неверные данные запроса"})
//			return
//		}
//
//		// Проверяем, существует ли пользователь с таким именем
//		var exists bool
//		err := db.QueryRow("SELECT EXISTS (SELECT 1 FROM users WHERE username = $1)", user.Username).Scan(&exists)
//		if err != nil {
//			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка базы данных"})
//			return
//		}
//		if exists {
//			c.JSON(http.StatusConflict, gin.H{"error": "Пользователь уже существует"})
//			return
//		}
//
//		// Генерируем хэш пароля
//		hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
//		if err != nil {
//			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при создании хэша пароля"})
//			return
//		}
//
//		// Сохраняем пользователя с ролью "user" в базе данных
//		_, err = db.Exec("INSERT INTO users (username, password, role) VALUES ($1, $2, $3)", user.Username, hash, "user")
//		if err != nil {
//			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при регистрации пользователя"})
//			return
//		}
//
//		// Генерация JWT токена
//		token, err := middleware.GenerateJWT(user.Username, "user")
//		if err != nil {
//			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при генерации токена"})
//			return
//		}
//
//		// Генерация refresh токена
//		refreshToken, err := middleware.GenerateRefreshToken(user.Username, "user")
//		if err != nil {
//			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при генерации refresh токена"})
//			return
//		}
//
//		// Сохраняем refresh токен в базе данных
//		_, err = db.Exec("INSERT INTO refresh_tokens (username, token) VALUES ($1, $2)", user.Username, refreshToken)
//		if err != nil {
//			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при сохранении refresh токена"})
//			return
//		}
//
//		//// Возвращаем токен доступа и refresh токен
//		c.JSON(http.StatusOK, gin.H{
//			"message":      "Регистрация прошла успешно",
//			"token":        token,        // Access токен
//			"refreshToken": refreshToken, // Refresh токен
//		})
//
//		//// Изменение: возвращаем токены через заголовки ответа
//		//c.Header("AuthToken", token)           // Access токен
//		//c.Header("RefreshToken", refreshToken) // Refresh токен
//		//
//		//// Возвращаем сообщение о регистрации
//		//c.JSON(http.StatusOK, gin.H{
//		//	"message": "Регистрация прошла успешно",
//		//})
//
//	}
//}
