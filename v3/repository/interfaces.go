package repository

import (
	"apiP/v3/dto"
	"database/sql"
	"github.com/google/uuid"
	"time"
)

// User представляет пользователя.
type User struct {
	Id                string
	Username          sql.NullString
	Email             sql.NullString
	Phone             sql.NullString
	Role              sql.NullString
	Status            sql.NullString
	PasswordUpdatedAt sql.NullTime //PasswordUpdatedAt *time.Time
	CreatedAt         sql.NullTime //CreatedAt         *time.Time
	LastLogin         sql.NullTime //LastLogin         *time.Time
}

// UserRepository Общий интерфейс
type UserRepository interface {
	UserReader
	UserExists
	UserWriter
	UserValidator
}

//////
// Интерфейсы

type UserReader interface {
	GetUsers(limit, offset int) ([]map[string]interface{}, int, error)                // Получение списка пользователей
	FetchUser(field, value string) (string, string, string, string, time.Time, error) // Получение id, password, role, status, password_updated_at пользователя
}

type UserExists interface {
	ExistsById(userID string) (bool, error)
}

type UserWriter interface {
	UpdateUser(id string, data dto.UpdateUserData) error // Обновление данных пользователя
	DeleteUser(id string) error                          // Удаление пользователя
	InsertUser(userID *uuid.UUID, username, email, phone *string, passwordHash []byte) (*uuid.UUID, error)
	UpdateLastLogin(userID string, lastLogin time.Time) error // Обновить последний вход
	UpdateStatus(userID, status string) error                 // Обновить статус пользователя
	UpdateUserRole(userID, role string) error                 // Обновить роль пользователя
	InsertToBlackList(token string) error
}

type UserValidator interface { // Проверка уникальности пользователя
	CheckUsernameUniqueness(username *string) error
	CheckEmailUniqueness(email *string) error
	CheckPhoneUniqueness(phone *string) error
}

////////
