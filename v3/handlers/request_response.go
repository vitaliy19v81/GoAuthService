package handlers

//type UpdateUserRequest struct {
//	Username string `json:"username" example:"new_username"`
//	Role     string `json:"role" example:"admin"`
//}

type UpdateUserRequest struct {
	Username          *string `json:"username" example:"new_username"`
	Email             *string `json:"email" example:"new_email@example.com"`
	Phone             *string `json:"phone" example:"1234567890"`
	Role              *string `json:"role" example:"admin"`
	Status            *string `json:"status" example:"active"`
	PasswordUpdatedAt *string `json:"password_updated_at" example:"2024-12-25T15:04:05Z"`
	CreatedAt         *string `json:"created_at" example:"2024-12-01T12:00:00Z"`
	LastLogin         *string `json:"last_login" example:"2024-12-20T18:30:00Z"`
}

type UpdateUserStatusRequest struct {
	Status *string `json:"status" example:"active"`
}

type UpdateUserRoleRequest struct {
	Role *string `json:"role" example:"user"`
}

type UpdateUserByLoginRequest struct {
	Identifier *string `json:"identifier"`
	Role       *string `json:"role"`
}

type SuccessResponse struct {
	Data         interface{} `json:"data"` // Используйте конкретный тип вместо `interface{}` (например, []User)
	TotalRecords int         `json:"totalRecords"`
	Limit        int         `json:"limit"`
	Offset       int         `json:"offset"`
}

type ErrorResponse struct {
	Error string `json:"error" example:"Описание ошибки"`
}

type MessageResponse struct {
	Message string `json:"message" example:"Операция выполнена успешно"`
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

type LoginRequest struct { // Общее логирование
	Username *string `json:"username,omitempty"`
	Password *string `json:"password"`
	Email    *string `json:"email,omitempty"`
	Phone    *string `json:"phone,omitempty"`
}

type RegisterRequest struct {
	Username *string `json:"username,omitempty"`
	Password *string `json:"password"`
	Email    *string `json:"email,omitempty"`
	Phone    *string `json:"phone,omitempty"`
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

type LoginByPhoneRequest struct {
	Password *string `json:"password" binding:"required"`
	Phone    *string `json:"phone" binding:"required"`
}

// RegisterByPhoneRequest Модель для документации Swagger
type RegisterByPhoneRequest struct {
	Phone    *string `json:"phone" binding:"required"`    // Телефон пользователя (обязательно)
	Password *string `json:"password" binding:"required"` // Пароль пользователя (обязательно)
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

type LoginByEmailRequest struct {
	Password *string `json:"password" binding:"required"`
	Email    *string `json:"email"  binding:"required"`
}

// RegisterRequestEmail Модель для документации Swagger
type RegisterRequestEmail struct {
	Email    *string `json:"email" binding:"required"`
	Password *string `json:"password" binding:"required"`
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
