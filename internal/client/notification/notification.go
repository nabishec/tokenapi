package notification

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/smtp"
	"os"
	"time"
)

var (
	from        = os.Getenv("FROM_EMAIL_ADRESS")
	password    = os.Getenv("SMTP_PASSWORD")
	hostName    = "smtp.mail.ru"
	addr        = "smtp.mail.ru:465"
	timeForSend = 2 * time.Second
)

func SendMessage(userMail string) error {
	const op = "internal.client.notification.SenMessage()"
	if from == "" || password == "" {
		return fmt.Errorf("%s:%s", op, "Server's mail data couldn`t be retrieved")
	}
	auth := smtp.PlainAuth("", from, password, hostName)
	msg := []byte("From: " + from + "\n" +
		"To: " + userMail + "\n" +
		"Subject: WARN\n" +
		"\n" +
		"Someone tried to log into your account")
	ctx, cancel := context.WithTimeout(context.Background(), timeForSend)
	defer cancel()

	errCH := make(chan error)

	go func() {
		conf := &tls.Config{ServerName: hostName}

		conn, err := tls.Dial("tcp", addr, conf)
		if err != nil {
			errCH <- fmt.Errorf("%s:%w", op, err)
		}

		cl, err := smtp.NewClient(conn, hostName)
		if err != nil {
			errCH <- fmt.Errorf("%s:%w", op, err)
		}

		if err = cl.Auth(auth); err != nil {
			errCH <- fmt.Errorf("%s:%w", op, err)
		}

		if err = cl.Mail(from); err != nil {
			errCH <- fmt.Errorf("%s:%w", op, err)
		}

		if err = cl.Rcpt(userMail); err != nil {
			errCH <- fmt.Errorf("%s:%w", op, err)
		}

		w, err := cl.Data()
		if err != nil {
			errCH <- fmt.Errorf("%s:%w", op, err)
		}

		if _, err = w.Write(msg); err != nil {
			errCH <- fmt.Errorf("%s:%w", op, err)
		}

		if err = w.Close(); err != nil {
			errCH <- fmt.Errorf("%s:%w", op, err)
		}

		if err = cl.Quit(); err != nil {
			errCH <- fmt.Errorf("%s:%w", op, err)
		}

		errCH <- nil
	}()

	var err error
	select {
	case err = <-errCH:
		return err
	case <-ctx.Done():
		return fmt.Errorf("%s:%s", op, "Time to send the message has expired")
	}

}
