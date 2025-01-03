// v3/handlers/register.go
package handlers

import (
	"apiP/v3/config"
	"apiP/v3/db_postgres"
	"apiP/v3/security"
	"apiP/v3/validation"
	"database/sql"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"log/slog"
	"net/http"
)

//// Регулярные выражения для email и phone
//var (
//	emailRegex = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)
//	phoneRegex = regexp.MustCompile(`^\+?\d{0,3}[-\s]?\(?\d{2,5}\)?[-\s]?\d{2,4}[-\s]?\d{2,4}[-\s]?\d{2,4}$`)
//)
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

//// checkUsernameUniqueness проверяет уникальность username.
//func checkUsernameUniqueness(db *sql.DB, username *string) error {
//
//	var exists bool
//	err := db.QueryRow("SELECT EXISTS (SELECT 1 FROM users WHERE username = $1)", username).Scan(&exists)
//	if err == nil && exists {
//		return fmt.Errorf("Имя пользователя уже занято")
//	}
//	return err
//}
//
//// checkEmailUniqueness проверяет уникальность email.
//func checkEmailUniqueness(db *sql.DB, email *string) error {
//	var exists bool
//	err := db.QueryRow("SELECT EXISTS (SELECT 1 FROM users WHERE email = $1)", email).Scan(&exists)
//	if err == nil && exists {
//		return fmt.Errorf("Электронная почта уже используется")
//	}
//	return err
//}
//
//// checkPhoneUniqueness проверяет уникальность phone.
//func checkPhoneUniqueness(db *sql.DB, phone *string) error {
//	var exists bool
//	err := db.QueryRow("SELECT EXISTS (SELECT 1 FROM users WHERE phone = $1)", phone).Scan(&exists)
//	if err == nil && exists {
//		return fmt.Errorf("Номер телефона уже используется")
//	}
//	return err
//}
//
//func insertUser(db *sql.DB, userID *uuid.UUID, username, email, phone *string, passwordHash []byte) (*uuid.UUID, error) {
//
//	// Вставляем данные нового пользователя в базу
//	query := `
//		INSERT INTO users (username, password, email, phone, role, status, password_updated_at, created_at)
//		VALUES ($1, $2, $3, $4, 'user', 'active', $5, $6) RETURNING id`
//	err := db.QueryRow(query, username, passwordHash, email, phone, time.Now().UTC(), time.Now().UTC()).Scan(&userID)
//	if err != nil {
//		return nil, fmt.Errorf("database error: %w", err)
//	}
//	return userID, nil
//}

// Проверка уникальности пользователя
func checkUniqueness(db *sql.DB, user RegisterRequest) error {

	if user.Username != nil {
		if err := db_postgres.CheckUsernameUniqueness(db, user.Username); err != nil {
			return err
		}
	}

	if user.Email != nil {
		if err := db_postgres.CheckEmailUniqueness(db, user.Email); err != nil {
			return err
		}
	}

	if user.Phone != nil {
		if err := db_postgres.CheckPhoneUniqueness(db, user.Phone); err != nil {
			return err
		}
	}

	return nil
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// RegisterByPhoneHandler обработчик для документации по упрощённой регистрации.
//
// @Summary Упрощённая регистрация нового пользователя
// @Description Регистрирует нового пользователя, указывая только телефон и пароль.
// @Tags auth
// @Accept json
// @Produce json
// @Param user body RegisterRequestPhone true "Данные пользователя для упрощённой регистрации"
// @Success 200 {object} map[string]string "message: Регистрация прошла успешно"
// @Failure 400 {object} map[string]string "error: Неверные данные запроса"
// @Failure 500 {object} map[string]string "error: Ошибка при регистрации пользователя"
// @Router /api/auth/register/phone [post]
func RegisterByPhoneHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var user RegisterRequestPhone

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

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// рабочий код

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

func validateFields(user *RegisterRequest, requiredFields []string) error {
	for _, field := range requiredFields {
		switch field {
		case "username":
			return validation.ValidateUsername(user.Username)

		case "email":
			return validation.ValidateEmail(user.Email)

		case "phone":
			return validation.ValidatePhone(user.Phone)

		case "password":
			return validation.ValidatePassword(user.Password)

		default:
			return fmt.Errorf("Invalid field in required fields")
		}
	}
	return nil
}

////////

//func checkPhoneUniqueness(db *sql.DB, phone *string) error {
//	var exists bool
//	err := db.QueryRow("SELECT EXISTS (SELECT 1 FROM users WHERE phone = $1)", phone).Scan(&exists)
//	if err != nil {
//		// Возвращаем обернутую ошибку для пользователя и разработчика
//		return errors.Wrap(err, "Ошибка проверки телефона")
//	}
//
//	if exists {
//		// Возвращаем стандартную пользовательскую ошибку
//		return errors.NewCustomError(errors.ErrPhoneInUse.Error(), nil)
//	}
//
//	// Ошибок нет
//	return nil
//}

///////////

//func insertUser(db *sql.DB, username, password, email, phone *string) error {
//	// Хэшируем пароль
//	hash, err := bcrypt.GenerateFromPassword([]byte(*password), bcrypt.DefaultCost)
//	if err != nil {
//		return fmt.Errorf("ошибка при создании хэша пароля: %w", err)
//	}
//
//	// Преобразуем хэш пароля в строку
//	//passwordHashStr := base64.StdEncoding.EncodeToString(hash)
//
//	// Вставляем данные нового пользователя в базу
//	_, err = db.Exec(
//		`INSERT INTO users (username, password, email, phone, role, status, password_updated_at, created_at)
//            VALUES ($1, $2, $3, $4, 'user', 'active', $5, $6)`,
//		username, hash, email, phone, time.Now().UTC(), time.Now().UTC(),
//	)
//	if err != nil {
//		return fmt.Errorf("ошибка при сохранении пользователя в базу данных: %w", err)
//	}
//
//	return nil
//}

//func insertUser(db *sql.DB, username, email, phone *string, passwordHash []byte) error {
//	_, err := db.Exec(
//		`INSERT INTO users (username, password, email, phone, role, status, password_updated_at, created_at)
//         VALUES ($1, $2, $3, $4, 'user', 'active', $5, $6)`,
//		username, passwordHash, email, phone, time.Now().UTC(), time.Now().UTC(),
//	)
//	if err != nil {
//		return fmt.Errorf("database error: %w", err)
//	}
//	return nil
//}

///////////////////

//func insertUser(db *sql.DB, user *RegisterRequest, passwordHash []byte) error {
//	_, err := db.Exec(
//		`INSERT INTO users (username, password, email, phone, role, status, password_updated_at, created_at)
//         VALUES ($1, $2, $3, $4, 'user', 'active', $5, $6)`,
//		user.Username, passwordHash, user.Email, user.Phone, time.Now().UTC(), time.Now().UTC(),
//	)
//	if err != nil {
//		return fmt.Errorf("database error: %w", err)
//	}
//	return nil
//}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

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
