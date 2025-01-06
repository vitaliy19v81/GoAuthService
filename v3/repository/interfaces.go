package repository

import (
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
	UserWriter
	UserValidator
}

//////
// Интерфейсы

type UserReader interface {
	GetUsers(limit, offset int) ([]map[string]interface{}, int, error)
	FetchUser(field, value string) (string, string, string, time.Time, error)
}

type UserWriter interface {
	UpdateUser(id, username, role string) error
	DeleteUser(id string) error
	InsertUser(userID *uuid.UUID, username, email, phone *string, passwordHash []byte) (*uuid.UUID, error)
}

type UserValidator interface {
	CheckUsernameUniqueness(username *string) error
	CheckEmailUniqueness(email *string) error
	CheckPhoneUniqueness(phone *string) error
}

////////
