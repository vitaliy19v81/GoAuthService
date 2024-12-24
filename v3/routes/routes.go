// v3/routes/routes.go
package routes

import (
	"apiP/v3/handlers"
	"apiP/v3/middleware"
	"database/sql"
	"github.com/gin-gonic/gin"
	"net/http"
)

func SetupRouter(router *gin.Engine, db *sql.DB) {

	admin := router.Group("/api/auth/admin") // раскомментировать , middleware.AuthMiddleware("admin"))
	{
		//admin.GET("/users", handlers.GetUsersHandler(db))
		admin.GET("/users", handlers.GetUsersHandlerDB(db))
		admin.PUT("/users/:id", handlers.UpdateUserHandler(db))
		admin.DELETE("/users/:id", handlers.DeleteUserHandler(db))
	}

	router.POST("/api/auth/register", handlers.RegisterHandlerDB(db))
	router.POST("/api/auth/logout", handlers.LogoutHandler)
	router.POST("/api/auth/login", handlers.LoginHandlerDB(db))

	router.GET("/api/auth/required-fields", handlers.GetRequiredFieldsHandler())  // Получить текущие обязательные поля
	router.POST("/api/auth/required-fields", handlers.SetRequiredFieldsHandler()) // Обновить список обязательных полей

	router.GET("/api/auth/login-fields", handlers.GetLoginFieldsHandler())
	router.GET("/api/auth/supported-login-fields", handlers.SupportedLoginFieldsHandler())

	router.POST("/api/auth/refresh-access-token", handlers.RefreshAccessToken) // Маршрут для обновления токена
	router.POST("/api/auth/assign-role", middleware.AuthMiddleware("admin"), handlers.AssignRoleHandler(db))

	router.GET("/api/auth/protected", middleware.AuthMiddleware("user"), handlers.ProtectedHandler)
	router.GET("/api/auth/editor", middleware.AuthMiddleware("editor"), handlers.EditorHandler)
	router.GET("/api/auth/admin", middleware.AuthMiddleware("admin"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "Admin access granted"})
	})

}
