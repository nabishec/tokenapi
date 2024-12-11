package auth

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt"

	"github.com/go-chi/render"

	"github.com/google/uuid"
	"github.com/nabishec/tokenapi/internal/client/notification"
	"github.com/nabishec/tokenapi/internal/lib"
	"github.com/nabishec/tokenapi/internal/models"
	"github.com/nabishec/tokenapi/internal/storage/postgresql/db"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type PostRefresh interface {
	AddNewToken(refHash string, userGUID uuid.UUID, userIP string, jti string, exp time.Time) error
	GetAndDeleteToken(userID string) (refHash string, userIP string, jti string, exp time.Time, err error)
	GetMail(userID uuid.UUID) (string, error)
}

type TokenRefresh struct {
	postRefresh PostRefresh
}

func NewRefresh(postRefresh PostRefresh) TokenRefresh {
	return TokenRefresh{
		postRefresh: postRefresh,
	}
}

// @Summary      Post Refresh Token
// @Tags         auth
// @Description  Обновление и выдача новых токенов
// @Accept       json
// @Produce      json
// @Param        tokens   body     models.Tokens  true   "Tokens"  Example: {"accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lwIjoiMS4yMy4yMzQuNDUuNCJ9.AVN8t1_pQWU6iQjLq43-uHpLzoTBDo5hGmM9fq5Oe0M", "refreshToken": "ZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5LmV5SjFjMlZ5WDJsd0lqb2lNUzR5TXk0eU16UXVORFV1TkNKOS5BVk44dDFfcFFXVTZpUWpMcTQzLXVIcEx6b1RCRG81aEdtTTlmcTVPZTBN"}
// @Success      200        {object}  models.Tokens    "Tokens created successful"
// @Failure      400        {object}  models.Response     "Incorrect request"
// @Failure      403        {object}  models.Response     "Failed to determine IP"
// @Failure      404        {object}  models.Response     "User not found"
// @Failure      500        {object}  models.Response     "Server error(failed create tokens)"
// @Router       /tokenapi/v1/auth/refresh [post]
func (h *TokenRefresh) RefreshToken(w http.ResponseWriter, r *http.Request) {
	const op = "internal.server.handlers.auth.RefreshToken()"
	logs := log.With().Str("fn", op).Logger()
	logs.Info().Msg("Request for refresh tokens has been received")

	userIP, err := GetIP(r)
	if err != nil {
		logs.Error().AnErr(lib.ErrReader(err)).Msg("Failed to determine user IP")

		w.WriteHeader(http.StatusForbidden) // 403
		render.JSON(w, r, models.StatusError("failed to determine IP"))
		return
	}
	logs.Debug().Msgf("IP was defined as - %s", userIP)
	//read req
	var req models.Tokens
	err = json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		if errors.Is(err, io.EOF) {
			log.Error().Msg("request body is empty")
		} else {
			log.Error().Err(err).Msg("failed to decode request body")
		}

		w.WriteHeader(http.StatusBadRequest) // 400
		render.JSON(w, r, models.StatusError("incorrect request"))
		return
	}
	log.Info().Msgf("request body decoded. Access Token - %s Refresh Token - %s", req.AccessToken, req.RefreshToken)

	if err := validator.New().Struct(req); err != nil {
		validatorErr := err.(validator.ValidationErrors)
		log.Error().Err(err).Msg("invalid types")

		w.WriteHeader(http.StatusBadRequest) // 400
		render.JSON(w, r, models.StatusError(validatorErr.Error()))
		return
	}

	// check access token
	accessToken, err := JWTTokenValid(req.AccessToken)
	if err != nil && err != ErrAccessTokenExpired || accessToken == nil {
		logs.Error().AnErr(lib.ErrReader(err)).Msg("Invalid access token")

		w.WriteHeader(http.StatusBadRequest) // 400
		render.JSON(w, r, models.StatusError("invalid access token"))
		return
	}

	//decode refresh
	refreshDecoded, err := DecodeRefresh(req.RefreshToken)
	if err != nil {
		logs.Error().AnErr(lib.ErrReader(err)).Msg("Failed decoded refresh token")

		w.WriteHeader(http.StatusBadRequest) // 400
		render.JSON(w, r, models.StatusError("invalid refresh token"))
		return
	}
	log.Debug().Msgf("Refresh Token decoded, %s", refreshDecoded)

	//check refresh in bd
	refreshToken, refHash, err := h.GetRefreshTokenFromDB(accessToken.Subject)
	if err != nil {
		if err == db.ErrTokenNotExists {
			log.Error().Msgf("Refresh token of user id - %s not found", accessToken.Subject)

			w.WriteHeader(http.StatusNotFound) // 404
			render.JSON(w, r, models.StatusError("refresh token not fount"))
			return
		}

		logs.Error().AnErr(lib.ErrReader(err)).Msg("Can`t found and delete refresh token not found")

		w.WriteHeader(http.StatusInternalServerError) // 500
		render.JSON(w, r, models.StatusError("Failed to get payload from refresh token"))
		return
	}
	log.Debug().Msgf("Refresh Token exist in DB, %s", *refHash)

	//
	if refreshToken.Id != accessToken.Id {
		logs.Error().AnErr(lib.ErrReader(err)).Msg("Access token was issued not  for this  refresh token")

		w.WriteHeader(http.StatusBadRequest) // 400
		render.JSON(w, r, models.StatusError("invalid access token"))
		return
	}

	if refreshToken.ExpiresAt < time.Now().Unix() {
		logs.Error().AnErr(lib.ErrReader(err)).Msg("Refresh token is expired")

		w.WriteHeader(http.StatusBadRequest) // 400
		render.JSON(w, r, models.StatusError("invalid refresh token"))
		return
	}
	//

	err = CheckRefHash(*refHash, refreshDecoded)
	if err != nil {
		logs.Error().AnErr(lib.ErrReader(err)).Msg("Refresh token hash not valid")

		w.WriteHeader(http.StatusBadRequest) // 400
		render.JSON(w, r, models.StatusError("invalid refresh token"))
		return
	}
	log.Debug().Msgf("Refresh Token Valid")

	userIPInRefTok, err := DecodeUserIPFromRefTok(refreshDecoded)
	if err != nil {
		logs.Error().AnErr(lib.ErrReader(err)).Msg("Failed to decode refresh token")

		w.WriteHeader(http.StatusBadRequest) // 400
		render.JSON(w, r, models.StatusError("invalid refresh token"))
		return
	}
	log.Debug().Msgf("Ip from refresh payload received - %s", userIPInRefTok)

	if userIPInRefTok != refreshToken.UserIP || userIPInRefTok != userIP {
		logs.Error().Msg("Invalid IP")
		err = h.WarnMessage(accessToken.Subject, logs)
		if err != nil {
			logs.Error().Err(err).Msgf("Failed send warn message to user - %s", accessToken.Subject) //
		}
		w.WriteHeader(http.StatusBadRequest) // 400
		render.JSON(w, r, models.StatusError("Unknown IP"))
		return
	}

	NewAccessToken, jti, err := CreateAccessToken(accessToken.Subject, userIP)
	if err != nil {
		logs.Error().AnErr(lib.ErrReader(err)).Msg("Failed to create access-token")

		w.WriteHeader(http.StatusInternalServerError) // 500
		render.JSON(w, r, models.StatusError("failed to create access-token"))
		return
	}
	logs.Debug().Msgf("Access token for user - %s created successfull", accessToken.Subject)

	NewRefreshToken, err := CreateRefreshToken(userIP)
	if err != nil {
		logs.Error().Err(err).Msg("Failed to create refresh-token")

		w.WriteHeader(http.StatusInternalServerError) // 500
		render.JSON(w, r, models.StatusError("failed to create refresh-token"))
		return
	}
	logs.Debug().Msgf("Refresh token for user - %s created successfull", accessToken.Subject)

	NewRefHash, err := CreateHashRef(NewRefreshToken)
	if err != nil {
		logs.Error().AnErr(lib.ErrReader(err)).Msg("Failed to create refresh hash")

		w.WriteHeader(http.StatusInternalServerError) // 500
		render.JSON(w, r, models.StatusError("failed to create refresh-token"))
		return
	}
	logs.Debug().Msgf("Refresh hash for user - %s created successfull", accessToken.Subject)

	expRef := time.Now().Unix() + 86400 // one day
	err = h.postRefresh.AddNewToken(NewRefHash, uuid.MustParse(accessToken.Subject), userIP, jti, time.Unix(expRef, 0))
	if err != nil {
		if err == db.ErrUserNotExists {
			log.Error().Msgf("User id - %s not found", accessToken.Subject)
			w.WriteHeader(http.StatusNotFound) // 404
			render.JSON(w, r, models.StatusError("user id not fount"))
			return
		}
		logs.Error().AnErr(lib.ErrReader(err)).Msg("Failed to save refresh hash")

		w.WriteHeader(http.StatusInternalServerError) // 500
		render.JSON(w, r, models.StatusError("failed to save refresh-token"))
		return
	}
	logs.Debug().Msgf("Refresh hash for user - %s saved successfull", accessToken.Subject)
	NewRefreshToken = EncodeRefresh(NewRefreshToken)
	logs.Info().Msgf("Tokens created for user - %s", accessToken.Subject)
	resp := models.Tokens{
		AccessToken:  NewAccessToken,
		RefreshToken: NewRefreshToken,
	}
	w.WriteHeader(http.StatusOK) //200
	render.JSON(w, r, resp)

}

func (h *TokenRefresh) GetRefreshTokenFromDB(userGUIDFromAccessToken string) (*JWTClaims, *string, error) {
	refHashFromDB, userIP, jti, exp, err := h.postRefresh.GetAndDeleteToken(userGUIDFromAccessToken)
	if err != nil {
		return nil, nil, err
	}
	claims := JWTClaims{
		userIP,
		jwt.StandardClaims{
			Id:        jti,
			ExpiresAt: exp.Unix(),
		},
	}

	return &claims, &refHashFromDB, nil

}

func (h *TokenRefresh) WarnMessage(userGUID string, logs zerolog.Logger) error {
	userMail, err := h.postRefresh.GetMail(uuid.MustParse(userGUID))
	if err != nil {
		return err
	}
	logs.Debug().Msgf("User mail received successful - %s", userMail)
	err = notification.SendMessage(userMail)
	if err != nil {
		return err
	}

	logs.Debug().Msg("Warn Message send successful")
	return nil

}
