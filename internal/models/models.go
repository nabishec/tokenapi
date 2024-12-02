package models

type Tokens struct {
	AccessToken  string `json:"access_token" validate:"required"`
	RefreshToken string `json:"refresh_token" validate:"required"`
}
type Response struct {
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

func StatusError(msg string) Response {
	return Response{
		Status: "Error",
		Error:  msg,
	}
}
