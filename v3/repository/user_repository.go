package repository

import (
	"apiP/v3/config"
	"apiP/v3/dto"
	"apiP/v3/security"
	"database/sql"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"log"
	//"log"
	"time"
)

// userRepository реализация интерфейса UserRepository.
type userRepository struct {
	db *sql.DB
}

// NewUserRepository создает новый UserRepository.
func NewUserRepository(db *sql.DB) UserRepository {
	return &userRepository{db: db}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Реализация UserReader ///////////////////////////////////////////////////////////////////////////////////////////////

// GetUsers возвращает список пользователей и общее количество.
func (r *userRepository) GetUsers(limit, offset int) ([]map[string]interface{}, int, error) {
	var users []User
	var totalRecords int

	err := r.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&totalRecords)
	if err != nil {
		return nil, 0, err
	}

	rows, err := r.db.Query(`
		SELECT id, username, email, phone, role, status, password_updated_at, created_at, last_login 
		FROM users LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	for rows.Next() {
		var user User
		err := rows.Scan(
			&user.Id,
			&user.Username,
			&user.Email,
			&user.Phone,
			&user.Role,
			&user.Status,
			&user.PasswordUpdatedAt,
			&user.CreatedAt,
			&user.LastLogin,
		)
		if err != nil {
			return nil, 0, err
		}

		// Расшифровываем телефон, если он не пустой
		if user.Phone.Valid && user.Phone.String != "" {
			key := config.PhoneSecretKey
			decryptedPhone, err := security.DecryptPhoneNumber(user.Phone.String, key)
			if err != nil {
				return nil, 0, fmt.Errorf("failed to decrypt phone: %w", err)
			}
			user.Phone.String = decryptedPhone // log.Println(user.Phone.String)
		}

		users = append(users, user)
	}

	// Преобразование в плоскую структуру
	flatUsers := make([]map[string]interface{}, 0, len(users))
	for _, user := range users {
		flatUsers = append(flatUsers, flattenUser(user))
	}

	return flatUsers, totalRecords, nil
}

// flattenUser преобразует структуру User в плоскую.
func flattenUser(user User) map[string]interface{} {
	return map[string]interface{}{
		"id":                  user.Id,
		"username":            nullStringToString(user.Username),
		"email":               nullStringToString(user.Email),
		"phone":               nullStringToString(user.Phone),
		"role":                nullStringToString(user.Role),
		"status":              nullStringToString(user.Status),
		"password_updated_at": nullTimeToString(user.PasswordUpdatedAt),
		"created_at":          nullTimeToString(user.CreatedAt),
		"last_login":          nullTimeToString(user.LastLogin),
	}
}

// nullStringToString конвертирует sql.NullString в обычную строку.
func nullStringToString(ns sql.NullString) string {
	if ns.Valid {
		return ns.String
	}
	return ""
}

// nullTimeToString конвертирует sql.NullTime в строку формата времени.
func nullTimeToString(nt sql.NullTime) string {
	if nt.Valid {
		return nt.Time.Format("2006-01-02T15:04:05-07:00")
	}
	return ""
}

// nullTimeToPtr преобразует sql.NullTime в *time.Time.
func nullTimeToPtr(nt sql.NullTime) *time.Time {
	if nt.Valid {
		return &nt.Time
	}
	return nil
}

func (r *userRepository) FetchUser(field, value string) (string, string, string, string, time.Time, error) {
	var storedHash, storedRole, storedStatus string
	var passwordUpdatedAt time.Time
	var userID uuid.UUID

	query := fmt.Sprintf("SELECT id, password, role, status, password_updated_at FROM users WHERE %s = $1", field) // noinspection SqlDialectInspection
	err := r.db.QueryRow(query, value).Scan(&userID, &storedHash, &storedRole, &storedStatus, &passwordUpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", "", "", "", time.Time{}, fmt.Errorf("no user found for the provided field")
		}
		return "", "", "", "", time.Time{}, fmt.Errorf("database error: %w", err)
	}
	return userID.String(), storedHash, storedRole, storedStatus, passwordUpdatedAt, nil
}

// Реализация UserExists ///////////////////////////////////////////////////////////////////////////////////////////////

func (r *userRepository) ExistsById(userID string) (bool, error) {
	// Проверяем, существует ли пользователь
	var userExists bool
	err := r.db.QueryRow("SELECT EXISTS (SELECT 1 FROM users WHERE id = $1)", userID).Scan(&userExists)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return userExists, fmt.Errorf("user not found: %w", err)
		}
		return userExists, fmt.Errorf("database error: %w", err)
	}
	return userExists, nil
}

// Реализация UserWriter ///////////////////////////////////////////////////////////////////////////////////////////////

//// UpdateUser обновляет данные пользователя.
//func (r *userRepository) UpdateUser(id, username, role string) error {
//	_, err := r.db.Exec("UPDATE users SET username = $1, role = $2 WHERE id = $3", username, role, id)
//	return err
//}

func (r *userRepository) UpdateUser(id string, data dto.UpdateUserData) error {
	// Формируем динамический SQL-запрос
	query := "UPDATE users SET " // noinspection SqlDialectInspection
	params := []interface{}{}
	i := 1

	if data.Username != nil {
		query += "username = $" + fmt.Sprint(i) + ", "
		params = append(params, *data.Username)
		i++
	}
	if data.Email != nil {
		query += "email = $" + fmt.Sprint(i) + ", "
		params = append(params, *data.Email)
		i++
	}
	if data.Phone != nil {
		query += "phone = $" + fmt.Sprint(i) + ", "
		params = append(params, *data.Phone)
		i++
	}
	if data.Role != nil {
		query += "role = $" + fmt.Sprint(i) + ", "
		params = append(params, *data.Role)
		i++
	}
	if data.Status != nil {
		query += "status = $" + fmt.Sprint(i) + ", "
		params = append(params, *data.Status)
		i++
	}
	if data.PasswordUpdatedAt != nil {
		query += "password_updated_at = $" + fmt.Sprint(i) + ", "
		params = append(params, *data.PasswordUpdatedAt)
		i++
	}
	if data.CreatedAt != nil {
		query += "created_at = $" + fmt.Sprint(i) + ", "
		params = append(params, *data.CreatedAt)
		i++
	}
	if data.LastLogin != nil {
		query += "last_login = $" + fmt.Sprint(i) + ", "
		params = append(params, *data.LastLogin)
		i++
	}

	// Убираем последнюю запятую и пробел
	query = query[:len(query)-2]

	// Добавляем условие WHERE
	query += " WHERE id = $" + fmt.Sprint(i)
	params = append(params, id)

	// Выполняем запрос
	_, err := r.db.Exec(query, params...)
	return err
}

// DeleteUser удаляет пользователя.
func (r *userRepository) DeleteUser(id string) error {
	_, err := r.db.Exec("DELETE FROM users WHERE id = $1", id)
	return err
}

func (r *userRepository) InsertUser(userID *uuid.UUID, username, email, phone *string, passwordHash []byte) (*uuid.UUID, error) {
	query := `
		INSERT INTO users (username, password, email, phone, role, status, password_updated_at, created_at) 
		VALUES ($1, $2, $3, $4, 'user', 'active', $5, $6) RETURNING id`
	err := r.db.QueryRow(query, username, passwordHash, email, phone, time.Now().UTC(), time.Now().UTC()).Scan(&userID)
	if err != nil {
		return nil, fmt.Errorf("database error: %w", err)
	}
	return userID, nil
}

// UpdateLastLogin обновления времени последнего входа
func (r *userRepository) UpdateLastLogin(userID string, lastLogin time.Time) error {
	query := "UPDATE users SET last_login = $1 WHERE id = $2"
	_, err := r.db.Exec(query, lastLogin, userID)
	return err
}

// UpdateStatus обновления статуса пользователя
func (r *userRepository) UpdateStatus(userID, status string) error {
	query := "UPDATE users SET status = $1 WHERE id = $2"
	_, err := r.db.Exec(query, status, userID)
	return err
}

// UpdateUserRole обновления статуса пользователя
func (r *userRepository) UpdateUserRole(userID, role string) error {
	query := "UPDATE users SET role = $1 WHERE id = $2"
	_, err := r.db.Exec(query, role, userID)
	return err
}

func (r *userRepository) InsertToBlackList(token string) error {
	query := `
		INSERT INTO revoked_tokens (token, revoked_at) 
		VALUES ($1, $2)`
	//  RETURNING id //.Scan(&id)
	_, err := r.db.Exec(query, token, time.Now().UTC())
	if err != nil {
		log.Println(err)
		return fmt.Errorf("database error: %w", err)
	}
	return nil
}

// Реализация UserValidator ////////////////////////////////////////////////////////////////////////////////////////////

func (r *userRepository) CheckUsernameUniqueness(username *string) error {
	var exists bool
	err := r.db.QueryRow("SELECT EXISTS (SELECT 1 FROM users WHERE username = $1)", username).Scan(&exists)
	if err == nil && exists {
		return fmt.Errorf("Имя пользователя уже занято")
	}
	return err
}

func (r *userRepository) CheckEmailUniqueness(email *string) error {
	var exists bool
	err := r.db.QueryRow("SELECT EXISTS (SELECT 1 FROM users WHERE email = $1)", email).Scan(&exists)
	if err == nil && exists {
		return fmt.Errorf("Электронная почта уже используется")
	}
	return err
}

func (r *userRepository) CheckPhoneUniqueness(phone *string) error {
	var exists bool
	err := r.db.QueryRow("SELECT EXISTS (SELECT 1 FROM users WHERE phone = $1)", phone).Scan(&exists)
	if err == nil && exists {
		return fmt.Errorf("Номер телефона уже используется")
	}
	return err
}
