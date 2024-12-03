package db

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v4"
	"github.com/rs/zerolog/log"
)

var (
	ErrUserNotExists  = errors.New("user's id doesn't exist")
	ErrTokenNotExists = errors.New("token not found")
)

func (r *Database) AddNewToken(refHash string, userID uuid.UUID, userIP string, jti string, exp time.Time) error {
	const op = "internal.storage.postgresql.db.AddToken()"

	err := r.userExist(userID)
	if err != nil {
		return err
	}
	log.Debug().Msgf("User with id - %s exist", userID.String())
	//delete old token if exist
	queryDeleteOldRef := "DELETE FROM Refresh_tokens WHERE user_id = $1"
	_, err = r.DB.Exec(queryDeleteOldRef, userID)
	if err != nil {
		return fmt.Errorf("%s:%w", op, err)
	}

	queryAddToken := `INSERT INTO Refresh_tokens (user_id, ref_hash, ip, jti, exp)
						VALUES ($1, $2, $3, $4, $5)
						RETURNING token_id`
	var tokenID int64
	err = r.DB.QueryRow(queryAddToken, userID, refHash, userIP, jti, exp).Scan(&tokenID)
	if err != nil {
		return fmt.Errorf("%s:%w", op, err)
	}
	log.Debug().Msgf("Refresh token with id(%d)  added succesfull", tokenID)

	return nil
}

func (r *Database) GetAndDeleteToken(userGUID string) (refHash string, userIP string, jti string, exp time.Time, err error) {
	const op = "internal.storage.postgresql.db.RefreshToken()"
	var tokenID int64
	queryGetParam := "SELECT token_id, ref_hash, ip, jti, exp FROM Refresh_tokens WHERE user_id = $1"
	err = r.DB.QueryRow(queryGetParam, userGUID).Scan(&tokenID, &refHash, &userIP, &jti, &exp)
	if err != nil {
		if err == pgx.ErrNoRows {
			err = ErrTokenNotExists
			return
		}
		err = fmt.Errorf("%s:%w", op, err)
		return
	}
	log.Debug().Msgf("Found token with token_id - %d", tokenID)
	// delete token after accessing it to ensure security
	queryDeleteToken := "DELETE FROM Refresh_tokens WHERE token_id = $1"
	_, err = r.DB.Exec(queryDeleteToken, tokenID)
	if err != nil {
		err = fmt.Errorf("%s:%w", op, err)
		return
	}
	log.Debug().Msgf("Token with id - %d deleted successful", tokenID)
	return
}

func (r *Database) userExist(userID uuid.UUID) error {
	const op = "internal.storage.postgresql.db.userExist()"
	var userNumber int
	query := "SELECT COUNT(*) FROM Users WHERE user_id = $1"

	err := r.DB.QueryRow(query, userID).Scan(&userNumber)
	if err != nil {
		return fmt.Errorf("%s:%w", op, err)
	}
	if userNumber == 0 {
		return ErrUserNotExists
	}
	return nil
}

func (r *Database) GetMail(userID uuid.UUID) (string, error) {
	const op = "internal.storage.postgresql.db.GetMail()"
	var userMail string
	query := "SELECT user_mail FROM Users WHERE user_id = $1"

	err := r.DB.QueryRow(query, userID).Scan(&userMail)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", ErrUserNotExists
		}
		return "", fmt.Errorf("%s:%w", op, err)
	}
	return userMail, nil
}
