package tpi_services

import (
	"encoding/json"
	jwt "github.com/dgrijalva/jwt-go"
	request "github.com/dgrijalva/jwt-go/request"
	"github.com/stratadigm/tpi_auth"
	"github.com/stratadigm/tpi_data"
	"golang.org/x/net/context"
	"google.golang.org/appengine/log"
	"net/http"
	"strconv"
)

func Login(c context.Context, requestUser *tpi_data.User) (int, []byte) {
	authBackend := tpi_auth.InitJWTAuthenticationBackend()

	if authBackend.Authenticate(c, requestUser) {
		token, err := authBackend.GenerateToken(strconv.Itoa(int(requestUser.Id)))
		if err != nil {
			return http.StatusInternalServerError, []byte("")
		} else {
			response, _ := json.Marshal(TokenAuthentication{token})
			return http.StatusOK, response
		}
	}

	return http.StatusUnauthorized, []byte("")
}

func RefreshToken(c context.Context, requestUser *tpi_data.User) []byte {

	empty := make([]byte, 0)
	authBackend := tpi_auth.InitJWTAuthenticationBackend()
	token, err := authBackend.GenerateToken(strconv.Itoa(int(requestUser.Id)))
	if err != nil {
		log.Errorf(c, "RefreshToken: generate token: %v\n", err)
		return empty
	}
	response, err := json.Marshal(TokenAuthentication{token})
	if err != nil {
		log.Errorf(c, "RefreshToken: json marshal: %v\n", err)
		return empty
	}
	return response

}

func Logout(c context.Context, req *http.Request) error {
	authBackend := tpi_auth.InitJWTAuthenticationBackend()
	tokenRequest, err := request.ParseFromRequest(req, request.OAuth2Extractor, func(token *jwt.Token) (interface{}, error) {
		return authBackend.PublicKey, nil
	})
	if err != nil {
		log.Errorf(c, "Logout: parse token from req: %v\n", err)
		return err
	}
	tokenString := req.Header.Get("Authorization")
	return authBackend.Logout(tokenString, tokenRequest)
}
