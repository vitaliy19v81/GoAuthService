// v3/db_postgres/db.go
package db_postgres

import (
	"apiP/v3/config"
	"database/sql"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"log"
)

func InitDB() (*sql.DB, error) {
	dsn := config.DsnPostgres // os.Getenv("DSN_POSTGRES")
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Проверка соединения
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return db, nil
}

func CreateUsersTable(db *sql.DB) error {
	query := `
	CREATE EXTENSION IF NOT EXISTS "pgcrypto"; -- Подключение расширения для генерации UUID
	CREATE TABLE IF NOT EXISTS users (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		username VARCHAR(255) UNIQUE DEFAULT NULL, -- Логин пользователя (опционально)
		email VARCHAR(255) UNIQUE DEFAULT NULL, -- Электронная почта для авторизации
	    phone VARCHAR(255) UNIQUE DEFAULT NULL, -- Телефон для авторизации
		password TEXT NOT NULL, -- Хэш пароля
		role VARCHAR(50) NOT NULL DEFAULT 'user', -- Роль пользователя
		status VARCHAR(50) NOT NULL DEFAULT 'active', -- Статус пользователя (active, inactive, banned, deleted)
		password_updated_at TIMESTAMPTZ NOT NULL DEFAULT now(), -- Время последнего обновления пароля
		created_at TIMESTAMPTZ NOT NULL DEFAULT now(), -- Время создания учётной записи
		last_login TIMESTAMPTZ -- Время последней авторизации
	);
	
	-- Создание индексов для оптимизации запросов
	CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
	CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
	CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
	CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);
	`
	_, err := db.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to create users table: %w", err)
	}
	return nil
}

// CreateBlackListTable Создание таблицы для черного списка токенов
func CreateBlackListTable(db *sql.DB) error {
	query := `
	CREATE TABLE IF NOT EXISTS revoked_tokens (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		token TEXT NOT NULL UNIQUE, -- Хранимый токен
		revoked_at TIMESTAMPTZ NOT NULL DEFAULT now() -- Время отзыва токена
	);
	
	-- Создание индексов для оптимизации поиска
	CREATE INDEX IF NOT EXISTS idx_revoked_tokens_token ON revoked_tokens(token);
	`
	_, err := db.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to create revoked tokens table: %w", err)
	}
	return nil
}

// CreateRefreshTokensTable создает таблицу для хранения refresh токенов (не используется)
func CreateRefreshTokensTable(db *sql.DB) error {
	query := `
	CREATE TABLE IF NOT EXISTS refresh_tokens (
		username VARCHAR(255) PRIMARY KEY,
		token TEXT NOT NULL
	);`
	_, err := db.Exec(query)
	if err != nil {
		return fmt.Errorf("failed to create refresh_tokens table: %w", err)
	}
	return nil
}

func CreateAdminUser(db *sql.DB) error {
	adminUsername := config.AdminUsername //os.Getenv("ADMIN_USERNAME")
	adminPassword := config.AdminPassword //os.Getenv("ADMIN_PASSWORD")

	if adminUsername == "" || adminPassword == "" {
		return fmt.Errorf("admin credentials not set in environment variables")
	}

	// Проверяем, существует ли администратор
	var exists bool
	err := db.QueryRow("SELECT EXISTS (SELECT 1 FROM users WHERE username = $1)", adminUsername).Scan(&exists)
	if err != nil {
		return fmt.Errorf("failed to check admin existence: %w", err)
	}

	if exists {
		log.Println("Admin user already exists")
		return nil
	}

	// Хешируем пароль
	hash, err := bcrypt.GenerateFromPassword([]byte(adminPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash admin password: %w", err)
	}

	// Вставляем администратора в таблицу
	_, err = db.Exec("INSERT INTO users (username, password, role) VALUES ($1, $2, $3)", adminUsername, hash, "admin")
	if err != nil {
		return fmt.Errorf("failed to create admin user: %w", err)
	}

	log.Println("Admin user created successfully")
	return nil
}

//func CreateUsersTable(db *sql.DB) error {
//	query := `
//	CREATE TABLE IF NOT EXISTS users (
//		id SERIAL PRIMARY KEY,
//		username VARCHAR(255) UNIQUE NOT NULL,
//		password TEXT NOT NULL,
//		role VARCHAR(50) NOT NULL DEFAULT 'user'
//	);`
//	_, err := db.Exec(query)
//	if err != nil {
//		return fmt.Errorf("failed to create users table: %w", err)
//	}
//	return nil
//}
