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
	"log"

	"net/http"
	"time"
)

// LoginByPhoneHandler авторизует пользователя с помощью логина и пароля, возвращая токен доступа.
//
// @Summary Авторизация пользователя
// @Description Авторизация с использованием логина и пароля. Возвращает JWT токен доступа и устанавливает refresh токен в Cookie.
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body handlers.LoginByPhoneRequest true "Данные для авторизации"
// @Success 200 {object} map[string]string "Успешный ответ с токеном доступа"
// @Failure 400 {object} map[string]string "Ошибка данных запроса"
// @Failure 401 {object} map[string]string "Неверные учетные данные"
// @Failure 403 {object} map[string]string "Срок действия пароля истёк"
// @Failure 429 {object} map[string]string "Слишком много запросов"
// @Failure 500 {object} map[string]string "Ошибка сервера"
// @Header 200 {string} Authorization "Bearer <токен доступа>"
// @Router /api/auth/login-by-phone [post]
func (h *Handler) LoginByPhoneHandler(c *gin.Context) {
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
	var user LoginByPhoneRequest
	if err := c.BindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Ошибка данных запроса"})
		return
	}

	if err := validation.ValidatePassword(user.Password); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Пароль слишком короткий"})
		return
	}

	if user.Phone != nil {
		if *user.Phone != "" {
			if !validation.PhoneRegex.MatchString(*user.Phone) {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Неверные данные для входа"})
				return
			}
		}
	}

	key := config.PhoneSecretKey
	value, err := security.EncryptPhoneNumber(*user.Phone, key)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при шифровании телефона"})
		return
	}

	// Получаем пользователя из репозитория
	userID, storedHash, storedRole, status, passwordUpdatedAt, err := h.userRepo.FetchUser("phone", value)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Неверные учетные данные"})
		return
	}

	if status == "deleted" {
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

// LoginByEmailHandler авторизует пользователя с помощью логина и пароля, возвращая токен доступа.
//
// @Summary Авторизация пользователя
// @Description Авторизация с использованием логина и пароля. Возвращает JWT токен доступа и устанавливает refresh токен в Cookie.
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body handlers.LoginByEmailRequest true "Данные для авторизации"
// @Success 200 {object} map[string]string "Успешный ответ с токеном доступа"
// @Failure 400 {object} map[string]string "Ошибка данных запроса"
// @Failure 401 {object} map[string]string "Неверные учетные данные"
// @Failure 403 {object} map[string]string "Срок действия пароля истёк"
// @Failure 429 {object} map[string]string "Слишком много запросов"
// @Failure 500 {object} map[string]string "Ошибка сервера"
// @Header 200 {string} Authorization "Bearer <токен доступа>"
// @Router /api/auth/login-by-email [post]
func (h *Handler) LoginByEmailHandler(c *gin.Context) {
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
	var user LoginByEmailRequest
	if err := c.BindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Ошибка данных запроса"})
		return
	}

	if err := validation.ValidatePassword(user.Password); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Пароль слишком короткий"})
		return
	}

	if user.Email != nil {
		if *user.Email != "" {
			if !validation.EmailRegex.MatchString(*user.Email) {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Неверные данные для входа"})
				return
			}
		}
	}

	// Получаем пользователя из репозитория
	userID, storedHash, storedRole, status, passwordUpdatedAt, err := h.userRepo.FetchUser("email", *user.Email)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Неверные учетные данные"})
		return
	}

	if status == "deleted" {
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
	userID, storedHash, storedRole, status, passwordUpdatedAt, err := h.userRepo.FetchUser(field, value)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Неверные учетные данные"})
		return
	}
	log.Println(status)

	if status == "deleted" {
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
