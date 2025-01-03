package db_postgres

import (
	"database/sql"
	"fmt"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"time"
)

// CheckUsernameUniqueness проверяет уникальность username.
func CheckUsernameUniqueness(db *sql.DB, username *string) error {
	var exists bool
	err := db.QueryRow("SELECT EXISTS (SELECT 1 FROM users WHERE username = $1)", username).Scan(&exists)
	if err == nil && exists {
		return fmt.Errorf("Имя пользователя уже занято")
	}
	return err
}

// CheckEmailUniqueness проверяет уникальность email.
func CheckEmailUniqueness(db *sql.DB, email *string) error {
	var exists bool
	err := db.QueryRow("SELECT EXISTS (SELECT 1 FROM users WHERE email = $1)", email).Scan(&exists)
	if err == nil && exists {
		return fmt.Errorf("Электронная почта уже используется")
	}
	return err
}

// CheckPhoneUniqueness проверяет уникальность phone.
func CheckPhoneUniqueness(db *sql.DB, phone *string) error {
	var exists bool
	err := db.QueryRow("SELECT EXISTS (SELECT 1 FROM users WHERE phone = $1)", phone).Scan(&exists)
	if err == nil && exists {
		return fmt.Errorf("Номер телефона уже используется")
	}
	return err
}

// InsertUser добавляет нового пользователя в базу данных.
func InsertUser(db *sql.DB, userID *uuid.UUID, username, email, phone *string, passwordHash []byte) (*uuid.UUID, error) {
	query := `
		INSERT INTO users (username, password, email, phone, role, status, password_updated_at, created_at) 
		VALUES ($1, $2, $3, $4, 'user', 'active', $5, $6) RETURNING id`
	err := db.QueryRow(query, username, passwordHash, email, phone, time.Now().UTC(), time.Now().UTC()).Scan(&userID)
	if err != nil {
		return nil, fmt.Errorf("database error: %w", err)
	}
	return userID, nil
}

func FetchUserFromDB(db *sql.DB, field, value string) (string, string, string, time.Time, error) {
	var storedHash, storedRole string
	var passwordUpdatedAt time.Time
	var userID uuid.UUID

	query := fmt.Sprintf("SELECT id, password, role, password_updated_at FROM users WHERE %s = $1", pq.QuoteIdentifier(field))
	err := db.QueryRow(query, value).Scan(&userID, &storedHash, &storedRole, &passwordUpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", "", "", time.Time{}, fmt.Errorf("no user found for the provided field")
		}
		return "", "", "", time.Time{}, fmt.Errorf("database error: %w", err)
	}

	return userID.String(), storedHash, storedRole, passwordUpdatedAt, nil
}

//// Проверка уникальности пользователя
//func CheckUniqueness(db *sql.DB, user RegisterRequest) error {
//	var exists bool
//
//	if user.Username != nil {
//		err := db.QueryRow("SELECT EXISTS (SELECT 1 FROM users WHERE username = $1)", user.Username).Scan(&exists)
//		if err == nil && exists {
//			return fmt.Errorf("Имя пользователя уже занято")
//		}
//	}
//
//	if user.Email != nil {
//		err := db.QueryRow("SELECT EXISTS (SELECT 1 FROM users WHERE email = $1)", user.Email).Scan(&exists)
//		if err == nil && exists {
//			return fmt.Errorf("Электронная почта уже используется")
//		}
//	}
//
//	if user.Phone != nil {
//		err := db.QueryRow("SELECT EXISTS (SELECT 1 FROM users WHERE phone = $1)", user.Phone).Scan(&exists)
//		if err == nil && exists {
//			return fmt.Errorf("Номер телефона уже используется")
//		}
//	}
//
//	return nil
//}

//// CheckUniqueness проверяет уникальность username, email и phone.
//func CheckUniqueness(db *sql.DB, username, email, phone *string) error {
//	if username != nil {
//		if err := CheckUsernameUniqueness(db, username); err != nil {
//			return err
//		}
//	}
//	if email != nil {
//		if err := CheckEmailUniqueness(db, email); err != nil {
//			return err
//		}
//	}
//	if phone != nil {
//		if err := CheckPhoneUniqueness(db, phone); err != nil {
//			return err
//		}
//	}
//	return nil
//}
