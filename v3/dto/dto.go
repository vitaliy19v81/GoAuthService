// /home/vtoroy/GolandProjects/apiP/v3/dto/dto.go
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

// UpdateUserStatus описывает обновляемый статус пользователя.
type UpdateUserStatus struct {
	Status *string `json:"status"`
}

// UpdateUserRole описывает обновляемую роль пользователя.
type UpdateUserRole struct {
	Role *string `json:"role"`
}

type UpdateUserRoleByLogin struct { // Еще не используется
	Identifier *string `json:"identifier"`
	Role       *string `json:"role"`
}
