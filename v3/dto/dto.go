package dto

// UpdateUserData описывает обновляемые данные пользователя.
type UpdateUserData struct {
	Username          *string `json:"username"`
	Email             *string `json:"email"`
	Phone             *string `json:"phone"`
	Role              *string `json:"role"`
	Status            *string `json:"status"`
	PasswordUpdatedAt *string `json:"password_updated_at"`
	CreatedAt         *string `json:"created_at"`
	LastLogin         *string `json:"last_login"`
}
