package main

import (
	"fmt"
	"log"
	"os"

	"github.com/g-wilson/seba"
	"github.com/g-wilson/seba/app"

	"github.com/g-wilson/runtime/devserver"
	"github.com/joho/godotenv"
	"gopkg.in/square/go-jose.v2"
)

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}
}

func main() {
	listenAddr := "127.0.0.1:" + os.Getenv("HTTP_PORT")

	keyset := &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{},
	}

	key := jose.JSONWebKey{}
	err := key.UnmarshalJSON([]byte(os.Getenv("SEBA_PRIVATE_KEY")))
	if err != nil {
		panic("error parsing key")
	}

	keyset.Keys = append(keyset.Keys, key)

	authenticator := devserver.NewAuthenticator(keyset, os.Getenv("SEBA_ISSUER"))
	server := devserver.New(listenAddr)

	appInstance, err := app.New()
	if err != nil {
		panic(err)
	}
	err = appInstance.Storage.Setup()
	if err != nil {
		panic(err)
	}

	server.AddService("auth", appInstance.AuthEndpoint(), nil)
	server.AddService("accounts", appInstance.AccountsEndpoint(), authenticator)

	tok, _ := appInstance.CreateClientAccessToken("debug", []string{seba.ScopeSebaAdmin})
	fmt.Println(fmt.Sprintf("client access token: %s", tok))

	server.Listen()
}
