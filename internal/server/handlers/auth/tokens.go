package auth

import (
	"encoding/base64"
	"fmt"
	"strings"

	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/bcrypt"
)

var SigningKey = []byte("TokenApi")
var ErrAccessTokenExpired = fmt.Errorf("token epired")

type JWTClaims struct {
	UserIP string `json:"user_ip"`
	jwt.StandardClaims
}

func CreateAccessToken(userGUID string, userIP string) (string, string, error) {

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
		return "", "", err
	}
	return tokenString, jti, err
}

func CreateRefreshToken(userIP string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, JWTClaims{UserIP: userIP})
	tokenString, err := token.SignedString(SigningKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func EncodeRefresh(tokenString string) string {
	ref := base64.RawURLEncoding.EncodeToString([]byte(tokenString))
	return ref
}

func DecodeRefresh(tokenString string) (string, error) {
	ref, err := base64.RawURLEncoding.DecodeString(tokenString)
	if err != nil {
		return "", err
	}
	return string(ref), nil
}

func CreateHashRef(ref string) (string, error) {
	str := strings.Split(ref, ".")
	if len(str) < 3 {
		return "", fmt.Errorf("invalid refresh token")
	}
	signature := str[2]
	log.Debug().Msgf("signature, %s", signature)
	refHash, err := bcrypt.GenerateFromPassword([]byte(signature), bcrypt.MinCost)
	if err != nil {
		return "", err
	}
	return string(refHash), nil

}

func CheckRefHash(refHash string, refToken string) error {
	str := strings.Split(refToken, ".")
	if len(str) < 3 {
		return fmt.Errorf("invalid refresh token")
	}
	signature := str[2]
	err := bcrypt.CompareHashAndPassword([]byte(refHash), []byte(signature))
	return err
}

func JWTTokenValid(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return SigningKey, nil
	})
	if err != nil {
		if valErr, ok := err.(*jwt.ValidationError); ok && valErr.Errors == jwt.ValidationErrorExpired {
			if claims, ok := token.Claims.(*JWTClaims); ok {
				log.Debug().Any("Token", claims)
				return claims, ErrAccessTokenExpired
			} else {
				return nil, fmt.Errorf("failed conversion of jwt claims")
			}
		}
		return nil, err
	}
	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	if claims, ok := token.Claims.(*JWTClaims); ok {
		log.Debug().Any("Token", claims)
		return claims, nil
	} else {
		return nil, fmt.Errorf("failed conversion of jwt claims")
	}
}

func DecodeUserIPFromRefTok(refToken string) (string, error) {
	refPayload, err := JWTTokenValid(string(refToken))
	if err != nil {
		return "", err
	}

	userIP := refPayload.UserIP
	return userIP, nil

}
