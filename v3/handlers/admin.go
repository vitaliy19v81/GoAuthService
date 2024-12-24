package handlers

import (
	"database/sql"
	"github.com/gin-gonic/gin"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"time"
)

func GetUsersHandlerDB(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Логирование параметров запроса
		log.Println("Query params:", c.Request.URL.Query())

		// Логирование заголовков
		log.Println("Headers:", c.Request.Header)

		// Логирование тела запроса (если есть)
		if c.Request.Body != nil {
			body, err := ioutil.ReadAll(c.Request.Body)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка чтения тела запроса"})
				return
			}
			log.Println("Request Body:", string(body))
		}

		//username := c.DefaultQuery("username", "")
		//role := c.DefaultQuery("role", "")
		//status := c.DefaultQuery("status", "")
		limitStr := c.DefaultQuery("length", "10")
		offsetStr := c.DefaultQuery("start", "0")

		limit, err := strconv.Atoi(limitStr)
		if err != nil || limit <= 0 {
			limit = 10
		}
		offset, err := strconv.Atoi(offsetStr)
		if err != nil || offset < 0 {
			offset = 0
		}

		//// Подсчёт записей после фильтрации
		//var filteredRecords int
		//err = db.QueryRow(`
		//	SELECT COUNT(*)
		//	FROM users
		//	WHERE
		//        ($1 = '' OR username ILIKE $1) AND
		//        ($2 = '' OR role ILIKE $2) AND
		//        ($3 = '' OR status ILIKE $3)`,
		//	"%"+username+"%", "%"+role+"%", "%"+status+"%").Scan(&filteredRecords)
		//if err != nil {
		//	c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при подсчёте записей"})
		//	return
		//}

		// Подсчёт общего количества записей
		var totalRecords int
		err = db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&totalRecords)
		if err != nil {
			log.Println("Ошибка при подсчёте общего числа записей")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при подсчёте общего числа записей"})
			return
		}

		//query := `
		//	SELECT id, username, email, phone, role, status, password_updated_at, created_at, last_login
		//	FROM users
		//	WHERE
		//        ($1 = '' OR username ILIKE $1) AND
		//        ($2 = '' OR role ILIKE $2) AND
		//        ($3 = '' OR status ILIKE $3)
		//	LIMIT $4 OFFSET $5
		//`

		//rows, err := db.Query(query, "%"+username+"%", "%"+role+"%", "%"+status+"%", limit, offset)
		//if err != nil {
		//	c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при получении данных пользователей"})
		//	return
		//}
		//defer rows.Close()

		// Подготавливаем запрос для получения данных пользователей
		query := `
			SELECT id, username, email, phone, role, status, password_updated_at, created_at, last_login 
			FROM users
			LIMIT $1 OFFSET $2
		`

		// Выполняем запрос
		rows, err := db.Query(query, limit, offset)
		if err != nil {
			log.Println("Ошибка при получении данных пользователей")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при получении данных пользователей"})
			return
		}
		defer rows.Close()

		var users []map[string]interface{}
		for rows.Next() {
			var user map[string]interface{}

			var id string
			var username, email, phone, role, status sql.NullString
			var passwordUpdatedAt, createdAt, lastLogin sql.NullTime

			err := rows.Scan(&id, &username, &email, &phone, &role, &status, &passwordUpdatedAt, &createdAt, &lastLogin)
			if err != nil {
				log.Println("Ошибка при чтении данных")
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при чтении данных"})
				return
			}

			user = map[string]interface{}{
				"id":                  id,
				"username":            nullStringToString(username),
				"email":               nullStringToString(email),
				"phone":               nullStringToString(phone),
				"role":                nullStringToString(role),
				"status":              nullStringToString(status),
				"password_updated_at": nullTimeToString(passwordUpdatedAt),
				"created_at":          nullTimeToString(createdAt),
				"last_login":          nullTimeToString(lastLogin),
			}
			users = append(users, user)
		}

		if err := rows.Err(); err != nil {
			log.Println("Ошибка обработки данных")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка обработки данных"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"data":         users,
			"totalRecords": totalRecords, // "recordsFiltered":filteredRecords,
			"limit":        limit,
			"offset":       offset,
		})
	}
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

//func GetUsersHandlerDB(db *sql.DB) gin.HandlerFunc {
//	return func(c *gin.Context) {
//		// Получаем параметры запроса
//		username := c.DefaultQuery("username", "")
//		role := c.DefaultQuery("role", "")
//		limitStr := c.DefaultQuery("limit", "10")  // Значение по умолчанию
//		offsetStr := c.DefaultQuery("offset", "0") // Значение по умолчанию
//
//		// Преобразуем limit и offset в числа
//		limit, err := strconv.Atoi(limitStr)
//		if err != nil || limit <= 0 {
//			limit = 10
//		}
//		offset, err := strconv.Atoi(offsetStr)
//		if err != nil || offset < 0 {
//			offset = 0
//		}
//
//		// Подсчёт общего количества записей
//		var totalRecords int
//		err = db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&totalRecords)
//		if err != nil {
//			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при подсчёте общего числа записей"})
//			return
//		}
//
//		// Подсчёт записей после фильтрации
//		var filteredRecords int
//		err = db.QueryRow(`
//			SELECT COUNT(*)
//			FROM users
//			WHERE username ILIKE $1 AND role ILIKE $2`,
//			"%"+username+"%", "%"+role+"%").Scan(&filteredRecords)
//		if err != nil {
//			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при подсчёте отфильтрованных записей"})
//			return
//		}
//
//		// Подготавливаем запрос
//		query := `
//			SELECT id, username, role, status, password_updated_at, created_at, last_login
//			FROM users
//			WHERE username ILIKE $1 AND role ILIKE $2
//			LIMIT $3 OFFSET $4
//		`
//
//		// Выполняем запрос
//		rows, err := db.Query(query, "%"+username+"%", "%"+role+"%", limit, offset)
//		if err != nil {
//			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при получении данных пользователей"})
//			return
//		}
//		defer rows.Close()
//
//		// Подготовка массива данных
//		var users []map[string]interface{}
//		for rows.Next() {
//			var id string
//			var username, role string
//			var passwordUpdatedAt time.Time
//
//			// Сканируем данные из БД
//			err := rows.Scan(&id, &username, &role, &passwordUpdatedAt)
//			if err != nil {
//				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при чтении данных пользователей"})
//				return
//			}
//
//			// Добавляем данные пользователя в массив
//			users = append(users, map[string]interface{}{
//				"id":                  id,
//				"username":            username,
//				"role":                role,
//				"password_updated_at": passwordUpdatedAt,
//			})
//		}
//
//		// Проверяем ошибки при итерации
//		if err := rows.Err(); err != nil {
//			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при обработке данных пользователей"})
//			return
//		}
//
//		// Возвращаем данные в формате JSON
//		c.JSON(http.StatusOK, gin.H{
//			"data": users,
//			//"recordsTotal":    totalRecords,
//			//"recordsFiltered": filteredRecords,
//			"limit":  limit,
//			"offset": offset,
//		})
//	}
//}

func UpdateUserHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		var input struct {
			Username string `json:"username"`
			Role     string `json:"role"`
		}
		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
			return
		}

		_, err := db.Exec("UPDATE users SET username = $1, role = $2 WHERE id = $3", input.Username, input.Role, id)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "User updated"})
	}
}

func DeleteUserHandler(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")
		log.Println(id)
		_, err := db.Exec("DELETE FROM users WHERE id = $1", id)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete user"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "User deleted"})
	}
}

// Рабочий код без ленивой прокрутки
//func GetUsersHandlerDB(db *sql.DB) gin.HandlerFunc {
//	return func(c *gin.Context) {
//		// Получаем данные пользователей из БД
//		rows, err := db.Query("SELECT id, username, role, password_updated_at FROM users")
//		if err != nil {
//			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при получении данных пользователей"})
//			return
//		}
//		defer rows.Close()
//
//		// Подготовка массива данных
//		var users []map[string]interface{}
//		for rows.Next() {
//			var id string
//			var username, role string
//			var passwordUpdatedAt time.Time
//
//			// Сканируем данные из БД
//			err := rows.Scan(&id, &username, &role, &passwordUpdatedAt)
//			if err != nil {
//				c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при чтении данных пользователей"})
//				return
//			}
//
//			// Добавляем данные пользователя в массив
//			users = append(users, map[string]interface{}{
//				"id":                  id,
//				"username":            username,
//				"role":                role,
//				"password_updated_at": passwordUpdatedAt,
//			})
//		}
//
//		// Проверяем ошибки при итерации
//		if err := rows.Err(); err != nil {
//			c.JSON(http.StatusInternalServerError, gin.H{"error": "Ошибка при обработке данных пользователей"})
//			return
//		}
//
//		// Возвращаем данные в формате JSON
//		c.JSON(http.StatusOK, gin.H{
//			"data": users,
//		})
//	}
//}

//func GetUsersHandler(db *sql.DB) gin.HandlerFunc {
//	return func(c *gin.Context) {
//		// Проверка роли администратора
//		if c.GetString("role") != "admin" {
//			c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
//			return
//		}
//
//		rows, err := db.Query("SELECT id, username, role, password_updated_at FROM users")
//		if err != nil {
//			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch users"})
//			return
//		}
//		defer rows.Close()
//
//		var users []map[string]interface{}
//		for rows.Next() {
//			var id, username, role string
//			var passwordUpdatedAt string
//			if err := rows.Scan(&id, &username, &role, &passwordUpdatedAt); err != nil {
//				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse user"})
//				return
//			}
//			users = append(users, map[string]interface{}{
//				"id":                  id,
//				"username":            username,
//				"role":                role,
//				"password_updated_at": passwordUpdatedAt,
//			})
//		}
//
//		c.JSON(http.StatusOK, users)
//	}
//}
