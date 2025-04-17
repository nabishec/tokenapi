package auth

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
)

var SigningKey = []byte(os.Getenv("SIGNING_KEY"))
var ErrAccessTokenExpired = fmt.Errorf("token expired")

type JWTClaims struct {
	UserIP string `json:"user_ip"`
	jwt.StandardClaims
}

func CreateAccessToken(userGUID string, userIP string) (string, string, error) {
	const op = "internal.server.handlers.auth.CreateAccessToken()"
	jti := uuid.New().String()
	exp := time.Now().Unix() + 900 // 15 minutes
	claims := JWTClaims{
		userIP,
		jwt.StandardClaims{
			Id:        jti,
			Subject:   userGUID,
			ExpiresAt: exp,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)

	tokenString, err := token.SignedString(SigningKey)

	if err != nil {
		return "", "", fmt.Errorf("%s:%w", op, err)
	}
	return tokenString, jti, nil
}

func CreateRefreshToken(userIP string) (string, error) {
	const op = "internal.server.handlers.auth.CreateRefreshToken()"
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, JWTClaims{
		userIP,
		jwt.StandardClaims{
			Id: uuid.NewString(),
		},
	})
	tokenString, err := token.SignedString(SigningKey)
	if err != nil {
		return "", fmt.Errorf("%s:%w", op, err)
	}

	return tokenString, nil
}

func EncodeRefresh(tokenString string) string {
	ref := base64.RawURLEncoding.EncodeToString([]byte(tokenString))
	return ref
}

func DecodeRefresh(tokenString string) (string, error) {
	const op = "internal.server.handlers.auth.DecodeRefresh()"
	ref, err := base64.RawURLEncoding.DecodeString(tokenString)
	if err != nil {
		return "", fmt.Errorf("%s:%w", op, err)
	}
	return string(ref), nil
}

func CreateHashRef(ref string) (string, error) {
	const op = "internal.server.handlers.auth.CreateHashRef()"
	str := strings.Split(ref, ".")
	if len(str) < 3 {
		return "", fmt.Errorf("%s:%s", op, "invalid refresh token")
	}
	signature := str[2]
	log.Debug().Msgf("signature, %s", signature)
	refHash, err := bcrypt.GenerateFromPassword([]byte(signature), bcrypt.MinCost)
	if err != nil {
		return "", fmt.Errorf("%s:%w", op, err)
	}
	return string(refHash), nil

}

func CheckRefHash(refHash string, refToken string) error {
	const op = "internal.server.handlers.auth.CheckRefHash()"
	str := strings.Split(refToken, ".")
	if len(str) < 3 {
		return fmt.Errorf("%s:%s", op, "invalid refresh token")
	}
	signature := str[2]
	err := bcrypt.CompareHashAndPassword([]byte(refHash), []byte(signature))
	if err != nil {
		return fmt.Errorf("%s:%w", op, err)
	}
	return nil
}

func JWTTokenValid(tokenString string) (*JWTClaims, error) {
	const op = "internal.server.handlers.auth.JWTTokenValid()"
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("%s:unexpected signing method: %v", op, token.Header["alg"])
		}
		return SigningKey, nil
	})
	if err != nil {
		if valErr, ok := err.(*jwt.ValidationError); ok && valErr.Errors == jwt.ValidationErrorExpired {
			if claims, ok := token.Claims.(*JWTClaims); ok {
				return claims, ErrAccessTokenExpired
			} else {
				return nil, fmt.Errorf("%s:%s", op, "failed conversion of jwt claims")
			}
		}
		return nil, err
	}
	if !token.Valid {
		return nil, fmt.Errorf("%s,%s", op, "invalid token")
	}
	if claims, ok := token.Claims.(*JWTClaims); ok {
		return claims, nil
	} else {
		return nil, fmt.Errorf("%s:%s", op, "failed conversion of jwt claims")
	}
}

func DecodeUserIPFromRefTok(refToken string) (string, error) {
	const op = "internal.server.handlers.auth.DecodeUserIPFromRefTok()"
	refPayload, err := JWTTokenValid(string(refToken))
	if err != nil {
		return "", fmt.Errorf("%s:%w", op, err)
	}

	userIP := refPayload.UserIP
	return userIP, nil

}
