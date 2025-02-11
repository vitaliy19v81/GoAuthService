// v3/routes/routes.go
package routes

import (
	"apiP/v3/handlers"
	"apiP/v3/middleware"
	"apiP/v3/repository"
	"database/sql"
	"github.com/gin-gonic/gin"
	"net/http"
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
	}
	router.POST("/api/auth/register/phone", handler.RegisterByPhoneHandler) // Регистрация по телефону и паролю
	router.POST("/api/auth/register/emile", handler.RegisterByEmailHandler) // Регистрации по почте и паролю
	router.POST("/api/auth/login", handler.LoginHandler)                    // Вход общий по username, email, phone
	router.POST("/api/auth/login-by-phone", handler.LoginByPhoneHandler)    // Вход по телефону и паролю
	router.POST("/api/auth/login-by-email", handler.LoginByEmailHandler)    // Вход по почте и паролю

	router.POST("/api/auth/logout", handler.LogoutHandler) // Выход

	// TODO перенаправление пользователей без требуемых прав

	admin := router.Group("/api/auth/admin0", middleware.AuthMiddleware("admin")) //, middleware.LoggingMiddleware())
	{
		//admin.GET("/users", handlers.GetUsersHandler(db))
		admin.GET("/users", handlers.GetUsersHandlerDB(db))
		admin.PUT("/users/:id", handlers.UpdateUserHandler(db))
		admin.DELETE("/users/:id", handlers.DeleteUserHandler(db))
	}

	router.POST("/api/auth/register", handlers.RegisterHandlerDB(db))                                       // Регистрация общая по username, email, phone
	router.PUT("/api/auth/assign-role", middleware.AuthMiddleware("admin"), handlers.AssignRoleHandler(db)) // Изменение роли по username, email, phone

	//router.POST("/api/auth/register/phone", handlers.RegisterByPhoneHandler(db)) //, middleware.LoggingMiddleware())
	//router.POST("/api/auth/register/emile", handlers.RegisterByEmailHandler(db))

	//router.POST("/api/auth/login", handlers.LoginHandlerDB(db), middleware.LoggingMiddleware())

	router.GET("/api/auth/required-fields", handlers.GetRequiredFieldsHandler())  // Получить текущие обязательные поля
	router.POST("/api/auth/required-fields", handlers.SetRequiredFieldsHandler()) // Обновить список обязательных полей

	router.GET("/api/auth/login-fields", handlers.GetLoginFieldsHandler())
	router.GET("/api/auth/supported-login-fields", handlers.SupportedLoginFieldsHandler())

	router.POST("/api/auth/refresh-access-token", handlers.RefreshAccessToken) // Маршрут для обновления токена

	router.GET("/api/auth/protected", middleware.AuthMiddleware("user"), handlers.ProtectedHandler)
	router.GET("/api/auth/editor", middleware.AuthMiddleware("editor"), handlers.EditorHandler)
	router.GET("/api/auth/admin", middleware.AuthMiddleware("admin"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "Admin access granted"})
	})

}
