package main

import (
	"fmt"
	"github.com/go-resty/resty/v2"
	"log"
)

const baseURL = "http://localhost:8080"

func main() {
	client := resty.New()

	// Логин администратора
	loginPayload := map[string]string{
		"username": "admin",
		"password": "securepassword",
	}
	var loginData struct {
		Token string `json:"token"`
	}
	_, err := client.R().SetBody(loginPayload).SetResult(&loginData).Post(baseURL + "/login")
	if err != nil {
		log.Fatalf("Error logging in as admin: %v", err)
	}
	adminToken := loginData.Token

	// Регистрация пользователя
	_, err = client.R().SetBody(map[string]string{
		"username": "editoruser3",
		"password": "password123",
	}).Post(baseURL + "/register")
	if err != nil {
		log.Fatalf("Error registering user: %v", err)
	}
	fmt.Println("User registered successfully")

	// Назначение роли
	_, err = client.R().
		SetAuthToken(adminToken).
		SetBody(map[string]string{
			"username": "editoruser",
			"role":     "editor",
		}).Post(baseURL + "/assign-role")
	if err != nil {
		log.Fatalf("Error assigning role: %v", err)
	}
	fmt.Println("Role assigned successfully")
}
