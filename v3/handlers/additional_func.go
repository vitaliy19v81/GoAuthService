package handlers

import (
	"apiP/v3/config"
	"apiP/v3/db_postgres"
	"apiP/v3/validation"
	"database/sql"
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
	"time"
)

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
