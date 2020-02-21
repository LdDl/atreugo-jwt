package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	jwt "github.com/LdDl/atreugo-jwt"
	"github.com/savsgio/atreugo/v10"
	"github.com/savsgio/go-logger"
	"github.com/valyala/fasthttp"
)

func main() {
	config := &atreugo.Config{
		Addr: ":" + "8080",
		PanicView: func(ctx *atreugo.RequestCtx, err interface{}) {
			logger.Printf("Panic error for request on \"%s\": %v\n", ctx.URI().Path(), err)
			log.Println(err)
			ctx.Error(errors.New("panic error").Error(), fasthttp.StatusInternalServerError)
		},
		CertKey:   "server.key",
		CertFile:  "server.crt",
		TLSEnable: false,
	}
	server := atreugo.New(config)

	api := server.NewGroupPath("/api")
	apiv001 := api.NewGroupPath("/v0.0.1")

	database := Database{
		UserData{
			Name:        "user",
			Password:    "pass",
			Description: "simple user",
			Access:      "Authentication",
		},
		UserData{
			Name:        "user2",
			Password:    "pass",
			Description: "simple user2",
			Access:      "Banned",
		},
	}

	jwtBus := InitAuth(database)
	api.POST("/doauth", jwtBus.LoginHandler)
	apiv001.GET("/refresh_token", jwtBus.RefreshHandler).UseBefore(jwtBus.MiddlewareFunc())
	apiv001.GET("/secret_page", SecretPage()).UseBefore(jwtBus.MiddlewareFunc())
	apiv001.GET("/public", Public())

	err := server.ListenAndServe()
	if err != nil {
		log.Println(err)
	}
}

func SecretPage() atreugo.View {
	return func(ctx *atreugo.RequestCtx) error {
		ctx.JSONResponse(map[string]string{"very": "secret"}, 200)
		return ctx.Next()
	}
}

func Public() atreugo.View {
	return func(ctx *atreugo.RequestCtx) error {
		ctx.JSONResponse(map[string]string{"not": "secret"}, 200)
		return ctx.Next()
	}
}

type UserData struct {
	Name        string
	Password    string
	Description string
	Access      string
}

type Database []UserData

func (db Database) CheckUser(login string) (UserData, error) {
	for i := range db {
		if db[i].Name == login {
			return db[i], nil
		}
	}
	return UserData{}, fmt.Errorf("No user")
}

type login struct {
	Username string `form:"username" json:"username" binding:"required"`
	Password string `form:"password" json:"password" binding:"required"`
}

func InitAuth(db Database) *jwt.AtreugoJWTMiddleware {
	identityKey := "login"
	authMiddleware, err := jwt.New(&jwt.AtreugoJWTMiddleware{
		Realm:            "atreugo",
		Key:              []byte("atreugo123"),
		Timeout:          time.Hour * 24,
		MaxRefresh:       time.Hour * 24,
		IdentityKey:      identityKey,
		SigningAlgorithm: "HS512",
		PayloadFunc: func(userId interface{}) jwt.MapClaims {
			user, _ := db.CheckUser(userId.(string))
			return jwt.MapClaims{
				"login": userId.(string),
				"desc":  user.Description,
			}
		},
		IdentityHandler: func(c *atreugo.RequestCtx) interface{} {
			claims := jwt.ExtractClaims(c)
			return &UserData{
				Name:        claims["login"].(string),
				Description: claims["desc"].(string),
			}
		},
		Authenticator: func(ctx *atreugo.RequestCtx) (interface{}, error) {
			loginVals := login{}
			bodyBytes := ctx.PostBody()
			if err := json.Unmarshal(bodyBytes, &loginVals); err != nil {
				return "", jwt.ErrMissingLoginValues
			}
			userID := loginVals.Username
			password := loginVals.Password
			user, err := db.CheckUser(userID)
			if err != nil {
				return userID, jwt.ErrFailedAuthentication
			}
			if password == user.Password && user.Access == "Authentication" {
				return userID, nil
			}
			return userID, jwt.ErrFailedAuthentication
		},
		Authorizator: func(userId interface{}, ctx *atreugo.RequestCtx) bool {
			user, err := db.CheckUser(userId.(*UserData).Name)
			if err != nil {
				return false
			}
			if user.Access == "Authentication" {
				return true
			}
			return false
		},
		Unauthorized: func(ctx *atreugo.RequestCtx, code int, message string) {
			if message == jwt.ErrFailedAuthentication.Error() {
				ctx.JSONResponse(jwt.H{"Error": string(ctx.Request.URI().Path()) + ";Unauthorized"}, 401)
				return
			}
			ctx.JSONResponse(jwt.H{"Error": string(ctx.Request.URI().Path()) + ";" + message}, 403)
			return
		},
		TokenLookup:   "header: Authorization, query: token, cookie: token",
		TokenHeadName: "Bearer",
		TimeFunc:      time.Now,
	})
	if err != nil {
		log.Println("Can not init auth")
		return nil
	}
	return authMiddleware
}
