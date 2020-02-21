# JWT Middleware for Atreugo Framework
## *preamble: this is cloned [appleyboy's](https://github.com/appleboy/gin-jwt/tree/v2.6.3) JWT middleware adapted for [Atreugo framework](https://github.com/savsgio/atreugo)*

### This is a middleware for [Atreugo](https://github.com/savsgio/atreugo) framework, which built on top of [fasthttp](https://github.com/valyala/fasthttp)

### **Be aware: version of Atreugo is 10.x.x (v10)**

It uses [jwt-go](https://github.com/dgrijalva/jwt-go) to provide a jwt authentication middleware. It provides additional handler functions to provide the `login` api that will generate the token and an additional `refresh` handler that can be used to refresh tokens.

## Usage

Download and install using [go module](https://blog.golang.org/using-go-modules):

```sh
export GO111MODULE=on
go get github.com/LdDl/atreugo-jwt
```

Import it in your code:

```go
import (
    jwt "github.com/LdDl/atreugo-jwt"
)
```

## Example

Please see [the example file](example/main.go)
```bash
go run example/main.go
```
Demo server will start on port 8080.

### Login API

Correct username/password and user access
```bash
curl -X POST 'http://localhost:8080/api/doauth' -d '{"username": "user", "password": "pass"}'
curl -X GET 'http://localhost:8080/api/v0.0.1/secret_page?token=PUT_RECIEVED_TOKEN'
```

Correct username/password but user has no access (banned)
```bash
curl -X POST 'http://localhost:8080/api/doauth' -d '{"username": "user2", "password": "pass"}'
```

Wrong user or password
```bash
curl -X POST 'http://localhost:8080/api/doauth' -d '{"username": "user", "password": "pass333"}'
```

### Refresh token API

```bash
curl -X GET 'http://localhost:8080/api/v0.0.1/refresh?token=PUT_RECIEVED_TOKEN'
```

### Login Flow

1. Authenticator: handles the login logic. On success LoginResponse is called, on failure Unauthorized is called.
2. LoginResponse: optional, allows setting a custom response such as a redirect.

### JWT Flow

1. PayloadFunc: maps the claims in the JWT.
2. IdentityHandler: extracts identity from claims.
3. Authorizator: receives identity and handles authorization logic.
4. Unauthorized: handles unauthorized logic.