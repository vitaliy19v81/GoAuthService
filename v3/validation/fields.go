// v3/validation/fields.go
package validation

import (
	"fmt"
	"regexp"
)

var (
	EmailRegex    = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)                                             // Валидация email
	PhoneRegex    = regexp.MustCompile(`^\+?\d{0,3}[-\s]?\(?\d{2,5}\)?[-\s]?\d{2,4}[-\s]?\d{2,4}[-\s]?\d{2,4}$`) // Валидация телефона
	UsernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]{3,}$`)
)

// ValidateUsername проверяет поле username.
func ValidateUsername(username *string) error {
	if username == nil || !EmailRegex.MatchString(*username) {
		return fmt.Errorf("invalid username, must be at least 3 characters long (a-zA-Z0-9_-)")
	}
	return nil
}

// ValidateEmail проверяет поле email.
func ValidateEmail(email *string) error {
	if email == nil || !EmailRegex.MatchString(*email) {
		return fmt.Errorf("invalid email address")
	}
	return nil
}

// ValidatePhone проверяет поле phone.
func ValidatePhone(phone *string) error {
	if phone == nil || !PhoneRegex.MatchString(*phone) {
		return fmt.Errorf("invalid phone number")
	}
	return nil
}

// ValidatePassword проверяет поле password.
func ValidatePassword(password *string) error {
	if password == nil || len(*password) < 6 {
		return fmt.Errorf("password must be at least 6 characters long")
	}
	return nil
}

// ^ — начало строки.
//[a-zA-Z0-9_-] — разрешены только буквы (верхний и нижний регистр), цифры, _ и -.
//{3,} — минимум 3 символа, без ограничения на максимум.
//$ — конец строки.
