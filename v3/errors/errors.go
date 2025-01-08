package errors

import "fmt"

// Пользовательские ошибки
var (
	ErrInvalidCredentials = fmt.Errorf("Неверные учетные данные")
	ErrPasswordExpired    = fmt.Errorf("Срок действия пароля истёк. Пожалуйста, смените пароль.")
	ErrPhoneInUse         = fmt.Errorf("Номер телефона уже используется")
)

// CustomError позволяет хранить более детальную информацию для разработчика
type CustomError struct {
	UserMessage string // Сообщение для пользователя
	DevMessage  error  // Сообщение для разработчика
}

func (e *CustomError) Error() string {
	if e.DevMessage != nil {
		return e.DevMessage.Error()
	}
	return e.UserMessage
}

// NewCustomError создает новый экземпляр CustomError
func NewCustomError(userMessage string, devMessage error) *CustomError {
	return &CustomError{
		UserMessage: userMessage,
		DevMessage:  devMessage,
	}
}

// Wrap позволяет обернуть любую ошибку
func Wrap(err error, userMessage string) *CustomError {
	return &CustomError{
		UserMessage: userMessage,
		DevMessage:  err,
	}
}
