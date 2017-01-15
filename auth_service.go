package tpi_services

import (
	"encoding/json"
	// jwt "github.com/dgrijalva/jwt-go"
	// request "github.com/dgrijalva/jwt-go/request"
	"github.com/stratadigm/tpi_auth"
	"github.com/stratadigm/tpi_data"
	"golang.org/x/net/context"
	"google.golang.org/appengine/log"
	"net/http"
	//"strconv"
	//"strings"
)

func Login(c context.Context, requestUser *tpi_data.User) (int, []byte) {

	authBackend := tpi_auth.InitJWTAuthenticationBackend()

	adsc := tpi_data.NewDSwc(c) //&tpi_data.DS{Ctx: c}
	validUser, err := adsc.GetUserwEmail(requestUser.Email)
	if err != nil {
		log.Errorf(c, "login invalid user %v \n", err)
		return http.StatusUnauthorized, []byte("")
	}

	if authBackend.Authenticate(validUser, requestUser) {
		//token, err := authBackend.GenerateToken(strconv.Itoa(int(requestUser.Id)))
		token, err := authBackend.GenerateToken(requestUser.Email)
		if err != nil {
			return http.StatusInternalServerError, []byte("")
		} else {
			response, _ := json.Marshal(token)
			return http.StatusOK, response //[]byte(token)
		}
	}

	return http.StatusUnauthorized, []byte("")

}

func RefreshToken(c context.Context, req *http.Request) (int, []byte) {

	empty := make([]byte, 0)
	authBackend := tpi_auth.InitJWTAuthenticationBackend()
	token, err := authBackend.RefreshToken(req)
	if err != nil {
		log.Errorf(c, "refresh token: generate token: %v\n", err)
		return http.StatusUnauthorized, empty
	}
	response, err := json.Marshal(token)
	if err != nil {
		log.Errorf(c, "refresh token: json marshal: %v\n", err)
		return http.StatusUnauthorized, empty
	}
	return http.StatusAccepted, response

}

func Logout(c context.Context, req *http.Request) error {

	authBackend := tpi_auth.InitJWTAuthenticationBackend()
	//tokenString := strings.TrimSpace(req.Header.Get("Authorization"))
	if tokStr, err := authBackend.Logout(req); err != nil {
		log.Errorf(c, "service logout %v \n", err)
		return nil

	} else { // valid unexpired token needs to be black listed after logout

		adsc := tpi_data.NewDSwc(c)
		if err1 := adsc.PutToken(tokStr); err != nil {
			log.Errorf(c, "service logout black list token %v \n", err1)
		}
		return nil
	}

}
