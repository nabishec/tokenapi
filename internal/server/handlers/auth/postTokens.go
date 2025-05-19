package auth

import (
	"net/http"
	"time"

	"github.com/go-chi/render"

	"github.com/google/uuid"
	"github.com/nabishec/tokenapi/internal/lib"
	"github.com/nabishec/tokenapi/internal/models"
	"github.com/nabishec/tokenapi/internal/storage/postgresql/db"
	"github.com/rs/zerolog/log"
)

type PostToken interface {
	AddNewToken(refHash string, userID uuid.UUID, userIP string, jti string, exp time.Time) error
}

type TokenIssuance struct {
	postToken PostToken
}

func NewTokenIssuance(postToken PostToken) TokenIssuance {
	return TokenIssuance{
		postToken: postToken,
	}
}

// @Summary      Post New Tokens
// @Tags         auth
// @Description  Генерация и выдача access и refresh токенов для клиента.
// @Accept       json
// @Produce      json
// @Param        client_id  query     string  true   "GUID user"  Example: "123e4567-e89b-12d3-a456-426614174000"
// @Success      200        {object}  models.Tokens    "Tokens created successful"
// @Failure      400        {object}  models.Response     "Incorrect value of user id"
// @Failure      403        {object}  models.Response     "Failed to determine IP"
// @Failure      404        {object}  models.Response     "User not found"
// @Failure      500        {object}  models.Response     "Server error(failed create tokens)"
// @Router       /tokenapi/v1/auth/token [post]
func (h *TokenIssuance) ReturnToken(w http.ResponseWriter, r *http.Request) {
	const op = "internal.server.handlers.auth.ReturnToken()"
	logs := log.With().Str("fn", op).Logger()
	logs.Info().Msg("Request for the issuance of tokens has been received")
	userGUID, err := uuid.Parse(r.URL.Query().Get("client_id"))
	if userGUID == uuid.Nil || err != nil {
		logs.Error().Msg("Failed to receive user GUID")

		w.WriteHeader(http.StatusBadRequest) // 400
		render.JSON(w, r, models.StatusError("incorrect value of user id"))
		return
	}
	logs.Debug().Msgf("User GUID - %s was received", userGUID)

	userIP, err := GetIP(r)
	if err != nil {
		logs.Error().AnErr(lib.ErrReader(err)).Msg("Failed to determine user IP")

		w.WriteHeader(http.StatusForbidden) // 403
		render.JSON(w, r, models.StatusError("failed to determine IP"))
		return
	}
	logs.Debug().Msgf("IP was defined as - %s", userIP)

	accessToken, jti, err := CreateAccessToken(userGUID.String(), userIP)
	if err != nil {
		logs.Error().AnErr(lib.ErrReader(err)).Msg("Failed to create access-token")

		w.WriteHeader(http.StatusInternalServerError) // 500
		render.JSON(w, r, models.StatusError("failed to create access-token"))
		return
	}
	logs.Debug().Msgf("Access token for user - %s created successfull", userGUID)

	refreshToken, err := CreateRefreshToken(userIP)
	if err != nil {
		logs.Error().AnErr(lib.ErrReader(err)).Msg("Failed to create refresh-token")

		w.WriteHeader(http.StatusInternalServerError) // 500
		render.JSON(w, r, models.StatusError("failed to create refresh-token"))
		return
	}
	logs.Debug().Msgf("Refresh token for user - %s created successfull", userGUID)

	refHash, err := CreateHashRef(refreshToken)
	if err != nil {
		logs.Error().AnErr(lib.ErrReader(err)).Msg("Failed to create refresh hash")

		w.WriteHeader(http.StatusInternalServerError) // 500
		render.JSON(w, r, models.StatusError("failed to create refresh-token"))
		return
	}
	logs.Debug().Msgf("Refresh hash for user - %s created successfull", userGUID)

	expRef := time.Now().Unix() + 86400 // one day
	err = h.postToken.AddNewToken(refHash, userGUID, userIP, jti, time.Unix(expRef, 0))
	if err != nil {
		if err == db.ErrUserNotExists {
			log.Error().Msgf("User id - %s not found", userGUID)
			w.WriteHeader(http.StatusNotFound) // 404
			render.JSON(w, r, models.StatusError("user id not fount"))
			return
		}
		logs.Error().AnErr(lib.ErrReader(err)).Msg("Failed to save refresh hash")
		w.WriteHeader(http.StatusInternalServerError) // 500
		render.JSON(w, r, models.StatusError("failed to save refresh-token"))
		return
	}
	logs.Debug().Msgf("Refresh hash for user - %s saved successfull", userGUID)

	logs.Info().Msgf("Tokens created for user - %s", userGUID)
	refreshToken = EncodeRefresh(refreshToken)
	resp := models.Tokens{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}
	w.WriteHeader(http.StatusOK) //200
	render.JSON(w, r, resp)
}
