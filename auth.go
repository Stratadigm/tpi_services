package tpi_services

import ()

type TokenAuthentication struct {
	Token string `json:"token" form:"token"`
}
