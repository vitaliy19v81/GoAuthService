// v3/handlers/register.go
package handlers

import (
	"apiP/v3/config"
	"apiP/v3/security"
	"apiP/v3/validation"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"log/slog"
	"net/http"
)

// example@example.com
//user.name@sub.domain.com
//user+tag@domain.co.uk
//1234567890@domain.com
//user_name@domain.com
//user-name@domain.io
//user@domain.travel
//email@localhost (при использовании локальных адресов).

// ^\+?: Опциональный символ + в начале.
//\d{0,3}: До трех цифр для кода страны.
//[-\s]?: Опциональный дефис или пробел.
//\(?\d{2,5}\)?: Код города/оператора (2–5 цифр), опционально в скобках.
//[-\s]?: Опциональный дефис или пробел.
//\d{2,4}: Блок из 2–4 цифр (основная часть номера).
//[-\s]?: Опциональный дефис или пробел.
//\d{2,4}: Еще один блок из 2–4 цифр.
//[-\s]?: Опциональный дефис или пробел.
//\d{2,4}$: Последний блок из 2–4 цифр.

// +1-800-555-0199
//+44 20 7946 0958
//+91 (22) 1234-5678
//+33-1-23-45-67-89
//+49 (30) 123 456 7890
//+7 495 123-45-67
//+86 10 1234 5678
//+1 (650) 555 1234
//+61 2 9876 5432
//+234 803 123 4567

//// Регулярные выражения для email и phone
//var (
//	emailRegex = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)
//	phoneRegex = regexp.MustCompile(`^\+?\d{0,3}[-\s]?\(?\d{2,5}\)?[-\s]?\d{2,4}[-\s]?\d{2,4}[-\s]?\d{2,4}$`)
//)
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

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
func (h *Handler) RegisterByEmailHandler(c *gin.Context) {
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

	if err := h.userRepo.CheckEmailUniqueness(user.Email); err != nil {
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
	if userID, err = h.userRepo.InsertUser(userID, nil, user.Email, nil, passwordHash); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при регистрации пользователя"})
		return
	}

	slog.Info("Пользователь успешно зарегистрирован", slog.String("userid", userID.String()))
	c.JSON(http.StatusOK, gin.H{"message": "Регистрация прошла успешно"})
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
func (h *Handler) RegisterByPhoneHandler(c *gin.Context) {
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
	if err := h.userRepo.CheckPhoneUniqueness(user.Phone); err != nil {
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
	if userID, err = h.userRepo.InsertUser(userID, nil, nil, user.Phone, passwordHash); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при регистрации пользователя"})
		return
	}

	slog.Info("Пользователь успешно зарегистрирован", slog.String("userid", userID.String()))
	c.JSON(http.StatusOK, gin.H{"message": "Регистрация прошла успешно"})
}
