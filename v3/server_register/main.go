// /apiP/v3/server_register/main.go
package main

import (
	auth "apiP/v3/auth_service"
	"apiP/v3/config"
	"apiP/v3/db_postgres"
	_ "apiP/v3/docs"
	authProto "apiP/v3/internal/services/auth_proto"
	"apiP/v3/routes"
	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq" // PostgreSQL драйвер
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"log"
	"net"
	"net/http"
)

//////////////////////////////////////////////////////////////////////////

//go get -u github.com/swaggo/swag/cmd/swag
//go get -u github.com/swaggo/gin-swagger
//go get -u github.com/swaggo/files

//export PATH=$PATH:$(go env GOPATH)/bin
//source ~/.bashrc
//echo $PATH
//swag init -g v3/server_register/main.go -o v3/docs

//////////////////////////////////////////////////////////////////////////

func main() {

	var err error

	// Загружаем конфигурацию (переменные окружения)
	config.LoadConfig()

	// Подключение к базе данных
	db, err := db_postgres.InitDB()
	if err != nil {
		log.Fatalf("Database initialization failed: %v", err)
	}
	defer db.Close()

	// Создание таблицы
	err = db_postgres.CreateUsersTable(db)
	if err != nil {
		log.Fatalf("Failed to create table: %v", err)
	}

	//if err := db_postgres.CreateRefreshTokensTable(db); err != nil {
	//	log.Fatalf("Error creating refresh_tokens table: %v", err)
	//}

	err = db_postgres.CreateBlackListTable(db)
	if err != nil {
		log.Fatalf("Failed to create table: %v", err)
	}

	// Создание администратора
	err = db_postgres.CreateAdminUser(db)
	if err != nil {
		log.Fatalf("Failed to create admin user: %v", err)
	}

	log.Println("Database setup completed successfully.")

	// Устанавливаем метод регистрации
	config.InitRequiredFields([]string{"phone", "password"}) // Регистрация только по email // "username", "email", "phone"

	// Устанавливаем возможные методы логина
	config.InitPossibleFields([]string{"username", "phone", "email"})

	router := gin.Default()

	// Настройка CORS (при необходимости)
	router.Use(func(c *gin.Context) {
		// Указываем конкретный домен, с которого разрешаем запросы
		//c.Writer.Header().Set("Access-Control-Allow-Origin", "*") // запросы со всех источников ("*"), что может быть
		// небезопасно, особенно если ваш сервис работает с конфиденциальными данными или требует авторизации.
		c.Writer.Header().Set("Access-Control-Allow-Origin", "http://localhost") // Укажите ваш фронтенд-домен // :3000
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")        // Для передачи cookie и авторизации
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		c.Writer.Header().Set("Access-Control-Expose-Headers", "Authorization") // Разрешить клиентам видеть заголовок (authToken)

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	})

	// go get -u github.com/swaggo/gin-swagger
	// go get -u github.com/swaggo/files

	url := ginSwagger.URL("http://localhost:8081/swagger/doc.json") // Указываем путь к JSON-документации

	router.GET("/swagger/*any", func(c *gin.Context) {
		// Если запрос на корневой путь /swagger/, редиректим на /swagger/index.html
		if c.Param("any") == "" || c.Param("any") == "/" {
			c.Redirect(http.StatusMovedPermanently, "/swagger/index.html")
			return
		}
		// Все остальные запросы обрабатывает Swagger Handler
		ginSwagger.WrapHandler(swaggerFiles.Handler, url)(c)
	})

	routes.SetupRouter(router, db)

	// У нас теперь WEB сервис
	//Запуск HTTP и gRPC серверов
	go func() {
		if err := router.Run("127.0.0.1:8081"); err != nil {
			log.Fatalf("Failed to run HTTP server: %v", err)
		}
	}()

	go func() {
		// Создаём gRPC сервер
		grpcServer := grpc.NewServer()

		// Регистрируем AuthServiceServer
		authService := auth.NewAuthServiceServer()
		authProto.RegisterAuthServiceServer(grpcServer, authService)

		// Включение reflection для gRPC
		reflection.Register(grpcServer)

		listener, err := net.Listen("tcp", ":50051")
		if err != nil {
			log.Fatalf("Failed to listen on port 50051: %v", err)
		}

		log.Println("gRPC server is running on port 50051")
		if err := grpcServer.Serve(listener); err != nil {
			log.Fatalf("Failed to serve gRPC server: %v", err)
		}
	}()

	// Ожидание завершения серверов
	select {}

}
