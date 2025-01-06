package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
)

// EncryptPhoneNumber шифрует телефон с использованием AES в режиме CBC.
// IV генерируется случайно и добавляется к результату.
func EncryptPhoneNumber(phone, key string) (string, error) {
	// Создаем AES-блок на основе переданного ключа
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Генерируем случайный IV
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return "", fmt.Errorf("failed to generate IV: %w", err)
	}

	// Добавляем PKCS7 padding
	paddingSize := aes.BlockSize - len(phone)%aes.BlockSize
	padding := make([]byte, paddingSize)
	for i := range padding {
		padding[i] = byte(paddingSize)
	}
	plainText := append([]byte(phone), padding...)

	// Шифруем данные
	cipherText := make([]byte, len(plainText))
	stream := cipher.NewCBCEncrypter(block, iv)
	stream.CryptBlocks(cipherText, plainText)

	// Присоединяем IV к шифрованному тексту
	result := append(iv, cipherText...)

	// Кодируем результат в Base64 для удобного хранения
	return base64.StdEncoding.EncodeToString(result), nil
}

// DecryptPhoneNumber расшифровывает телефон, зашифрованный с помощью EncryptPhoneNumber.
// IV извлекается из шифрованных данных.
func DecryptPhoneNumber(encryptedPhone, key string) (string, error) {
	// Декодируем base64-строку в шифрованный текст
	data, err := base64.StdEncoding.DecodeString(encryptedPhone)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64 encrypted phone: %w", err)
	}

	// Проверяем, что длина данных корректна
	if len(data) < aes.BlockSize || len(data)%aes.BlockSize != 0 {
		return "", errors.New("invalid encrypted data length")
	}

	// Извлекаем IV из первых 16 байт
	iv := data[:aes.BlockSize]
	cipherText := data[aes.BlockSize:]

	// Создаем AES-блок на основе переданного ключа
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Расшифровываем данные
	plainText := make([]byte, len(cipherText))
	stream := cipher.NewCBCDecrypter(block, iv)
	stream.CryptBlocks(plainText, cipherText)

	// Убираем PKCS7 padding
	paddingSize := int(plainText[len(plainText)-1])
	if paddingSize > aes.BlockSize || paddingSize > len(plainText) || paddingSize == 0 {
		return "", errors.New("invalid padding")
	}

	return string(plainText[:len(plainText)-paddingSize]), nil
}
