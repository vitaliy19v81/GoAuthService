package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

// generateIV детерминированно генерирует IV на основе телефона.
// Для этого используется хэш SHA-256, из которого берутся первые 16 байт.
func generateIV(phone string) ([]byte, error) {
	hash := sha256.Sum256([]byte(phone))
	return hash[:aes.BlockSize], nil // Берем первые 16 байт для IV
}

// EncryptPhoneNumber шифрует телефон с использованием AES в режиме CBC.
// Функция использует фиксированный IV, генерируемый на основе телефона.
// Это обеспечивает детерминированность шифрования (один и тот же телефон даст одинаковый шифр).
func EncryptPhoneNumber(phone, key string) (string, error) {
	// Создаем AES-блок на основе переданного ключа
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	// Генерируем IV для шифрования
	iv, err := generateIV(phone)
	if err != nil {
		return "", err
	}

	// Создаем CBC-шифровальщик
	stream := cipher.NewCBCEncrypter(block, iv)

	// Выравниваем данные до размера блока AES (PKCS7 Padding)
	paddingSize := aes.BlockSize - len(phone)%aes.BlockSize
	padding := make([]byte, paddingSize)
	for i := range padding {
		padding[i] = byte(paddingSize)
	}
	plainText := append([]byte(phone), padding...)

	// Шифруем данные
	cipherText := make([]byte, len(plainText))
	stream.CryptBlocks(cipherText, plainText)

	// Кодируем шифрованный текст в base64 для удобного хранения
	return base64.StdEncoding.EncodeToString(cipherText), nil
}

// DecryptPhoneNumber расшифровывает телефон, зашифрованный с помощью EncryptPhoneNumber.
// Использует тот же ключ и IV, что и для шифрования.
func DecryptPhoneNumber(encryptedPhone, phone, key string) (string, error) {
	// Создаем AES-блок на основе переданного ключа
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	// Генерируем IV на основе телефона
	iv, err := generateIV(phone)
	if err != nil {
		return "", err
	}

	// Декодируем base64-строку в шифрованный текст
	cipherText, err := base64.StdEncoding.DecodeString(encryptedPhone)
	if err != nil {
		return "", err
	}

	// Создаем CBC-расшифровальщик
	plainText := make([]byte, len(cipherText))
	stream := cipher.NewCBCDecrypter(block, iv)
	stream.CryptBlocks(plainText, cipherText)

	// Убираем добавленный padding  (PKCS7 Unpadding)
	paddingSize := int(plainText[len(plainText)-1])
	if paddingSize > aes.BlockSize || paddingSize == 0 {
		return "", errors.New("invalid padding")
	}
	return string(plainText[:len(plainText)-paddingSize]), nil
}

//package security
//
//import (
//	"crypto/aes"
//	"crypto/cipher"
//	"crypto/hmac"
//	"crypto/sha256"
//	"encoding/base64"
//	"encoding/hex"
//	"errors"
//	"fmt"
//)
//
//
//
//// EncryptPhoneNumber детерминированно шифрует номер телефона
//func EncryptPhoneNumber(phone, key string) (string, error) {
//	if len(key) == 0 {
//		return "", errors.New("ключ не может быть пустым")
//	}
//
//	h := hmac.New(sha256.New, []byte(key))
//	h.Write([]byte(phone))
//	return hex.EncodeToString(h.Sum(nil)), nil
//}
//
//// decryptPhoneNumber расшифровывает телефонный номер, зашифрованный с использованием AES.
//func decryptPhoneNumber(encryptedPhone, key string) (string, error) {
//	// Декодируем зашифрованный текст из Base64
//	data, err := base64.StdEncoding.DecodeString(encryptedPhone)
//	if err != nil {
//		return "", err
//	}
//
//	// Убеждаемся, что длина данных корректна
//	if len(data) < aes.BlockSize {
//		return "", errors.New("encrypted phone data is too short")
//	}
//
//	// Извлекаем IV и зашифрованный текст
//	iv := data[:aes.BlockSize]
//	ciphertext := data[aes.BlockSize:]
//
//	// Создаем AES-блок расшифровки
//	block, err := aes.NewCipher([]byte(key))
//	if err != nil {
//		return "", err
//	}
//
//	// Создаем расшифратор и расшифровываем данные
//	stream := cipher.NewCFBDecrypter(block, iv)
//	plaintext := make([]byte, len(ciphertext))
//	stream.XORKeyStream(plaintext, ciphertext)
//
//	return string(plaintext), nil
//}
//
//func Runcipher() {
//	phone := "+1234567890"
//	//key := "thisis32bitlongpassphrase1234567" // Должен быть длиной 32 байта для AES-256
//	key := "12345678901234567890123456789012"
//
//	// Шифруем телефонный номер
//	encryptedPhone, err := EncryptPhoneNumber(phone, key)
//	if err != nil {
//		fmt.Println("Ошибка при шифровании телефона:", err)
//		return
//	}
//	fmt.Println("Зашифрованный телефон:", encryptedPhone)
//
//	// Расшифровываем телефонный номер
//	decryptedPhone, err := decryptPhoneNumber(encryptedPhone, key)
//	if err != nil {
//		fmt.Println("Ошибка при расшифровке телефона:", err)
//		return
//	}
//	fmt.Println("Расшифрованный телефон:", decryptedPhone)
//}
