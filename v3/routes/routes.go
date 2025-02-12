// v3/routes/routes.go
package routes

import (
	"apiP/v3/handlers"
	"apiP/v3/middleware"
	"apiP/v3/repository"
	"database/sql"
	"github.com/gin-gonic/gin"
)

func SetupRouter(router *gin.Engine, db *sql.DB) {

	userRepo := repository.NewUserRepository(db)
	handler := handlers.NewHandler(userRepo)

	router.Use(middleware.RecoveryMiddleware())

	api := router.Group("/api/auth/admin", middleware.AuthMiddleware("admin"))
	{
		api.GET("/users", handler.GetUsersHandler)                       // Получение списка пользователей
		api.PUT("/users/:id", handler.UpdateUserHandler)                 // Обновление всех данных пользователя
		api.DELETE("/users/:id", handler.DeleteUserHandler)              // Удаление пользователя
		api.PUT("/users/:id/status", handler.UpdateUserStatusHandler)    // Обновление статуса пользователя
		api.PUT("/users/:id/assign-role", handler.UpdateUserRoleHandler) // Обновление роли пользователя по ID
		api.PUT("/users/assign-role", handler.UpdateUserByLoginHandler)  // Изменение роли по username, email, phone
	}
	router.POST("/api/auth/register/phone", handler.RegisterByPhoneHandler) // Регистрация по телефону и паролю
	router.POST("/api/auth/register/emile", handler.RegisterByEmailHandler) // Регистрации по почте и паролю
	router.POST("/api/auth/login", handler.LoginHandler)                    // Вход общий по username, email, phone
	router.POST("/api/auth/login-by-phone", handler.LoginByPhoneHandler)    // Вход по телефону и паролю
	router.POST("/api/auth/login-by-email", handler.LoginByEmailHandler)    // Вход по почте и паролю

	router.POST("/api/auth/logout", handler.LogoutHandler) // Выход

	router.POST("/api/auth/register", handlers.RegisterHandlerDB(db))                                       // Регистрация общая по username, email, phone
	router.PUT("/api/auth/assign-role", middleware.AuthMiddleware("admin"), handlers.AssignRoleHandler(db)) // Изменение роли по username, email, phone

	router.GET("/api/auth/required-fields", handlers.GetRequiredFieldsHandler())  // Получить текущие обязательные поля
	router.POST("/api/auth/required-fields", handlers.SetRequiredFieldsHandler()) // Обновить список обязательных полей

	router.GET("/api/auth/login-fields", handlers.GetLoginFieldsHandler())
	router.GET("/api/auth/supported-login-fields", handlers.SupportedLoginFieldsHandler())

	router.POST("/api/auth/refresh-access-token", handlers.RefreshAccessToken) // Маршрут для обновления токена

}
