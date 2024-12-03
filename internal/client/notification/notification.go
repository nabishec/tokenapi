package notification

import (
	"fmt"
	"net/smtp"
)

var (
	from     = ""
	password = ""
	hostName = "smtp.mail.ru"
	host     = ":465"
	msg      = []byte("WARN: кто-то пытался войти в ваш аккаунт с другого ip")
)

func SendMessage(userMail string) error {
	const op = "internal.client.notification.SenMessage()"
	to := []string{userMail}
	auth := smtp.PlainAuth("", from, password, hostName)
	err := smtp.SendMail((hostName + host), auth, from, to, msg)
	if err != nil {
		return fmt.Errorf("%s:%w", op, err)
	}
	return nil
}
