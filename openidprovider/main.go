package main

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
)

const (
	iss       = "https://localhost:8080"
	authnHTML = `<html>
<body>
AuthN?<br />

<form action="/authorize?%s" method="POST">
<label>ID: <input name="id" placeholder="userid"></label>
<label>Password: <input type="password" name="passwd" placeholder="passwd"></label>
<input type="submit">
</form>
</body>
</html>`
	authzHTML = `<html>
<body>
AuthZ?<br />
<a href="/authorize/yes?%s">YES</a>
<a href="/authorize/no?%s">NO</a>
</body>
</html>`
	// OpenID Connect 3.1.3.3
	// Successful Token Response
	tokenJSON = `{
  "access_token": "somethingToken",
  "token_type": "Bearer",
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAiLCJzdWIiOiIyNDQwMDMyMCIsImF1ZCI6ImNsaWVudCBhcHBsaWNhdGlvbiIsImV4cCI6MTMxMTI4MTk3MCwiaWF0IjoxMzExMjgwOTcwfQ.HPWARNhL212vwkH8FAJQ073rU9hoVHasZNQi0y-qkR5e_SyIIQ7a5Li5q6iyGf4UZfsjCwkdbRdW67PQiTMiuSXnE-8KKAyN1lo68RaqTK8Vkc58d6aq8jWyZs1FRIEFK2eG83mSrJP08rHQyzx2iRBtM3BX3kzPec2VaCxjUaQ",
}`
)

func main() { os.Exit(exec()) }

// main logic
func exec() int {
	// binding routes
	http.Handle(`/authorize`, logMiddleware(authzHandler))
	http.Handle(`/authenticate`, logMiddleware(authnHandler))
	http.Handle(`/authorize/yes`, logMiddleware(authzYesHandler))
	http.Handle(`/authorize/no`, logMiddleware(authzNoHandler))
	http.Handle(`/token`, logMiddleware(tokenHandler))

	// run http server
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Printf("%s", err)
		return 1
	}
	return 0
}

// HTTP handling middleware for logging
func logMiddleware(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf(`REQUEST: %s`, r.URL)
		h.ServeHTTP(w, r)
	})
}

// Authorization endpoint
func authzHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case `GET`: // GET method means the request is redirected from Client
		// OpenID Connect 3.1.2.2
		// Request Validation
		valid := true
		if !isOpenIDConnect(r.FormValue(`scope`)) {
			valid = false
		}
		responseType := r.FormValue(`response_type`)
		if responseType == "" {
			valid = false
		}
		clientID := r.FormValue(`client_id`)
		if clientID == "" {
			valid = false
		}
		redirectURI := r.FormValue(`redirect_uri`)
		if redirectURI == "" {
			valid = false
		}
		if !valid {
			w.Write([]byte(`this is not valie OpenID Connect Request`))
			return
		}

		// OpenID Connect 3.1.2.3
		// when the request is valid, redirect to authenticate endpoint
		// in this example, skip checking prompt parameter, but must check it in production
		// you can check user session before redirect
		w.Header().Set(`Location`, `/authenticate?`+r.Form.Encode())
		w.WriteHeader(http.StatusFound)
	case `POST`: // POST method means the request is authN request
		if !authenticate(r.FormValue(`id`), r.FormValue(`passwd`)) {
			// if the user authn is failed, re-redirect to authN endpoint
			w.Header().Set(`Location`, `authenticate?`+r.URL.Query().Encode())
			w.WriteHeader(http.StatusFound)
		}
		// OpenID Connect 3.1.2.4
		// authorize if the user authn is succeeded
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fmt.Sprintf(authzHTML, r.URL.Query().Encode(), r.URL.Query().Encode())))
	}
}

// Authentication Handler
// shows auth form
func authnHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(fmt.Sprintf(authnHTML, r.URL.Query().Encode())))
}

func authzYesHandler(w http.ResponseWriter, r *http.Request) {
	// OpenID Connect 3.1.2.5
	// Successful Authentication Response
	query := url.Values{}
	query.Add(`code`, `authorizedyes`)
	w.Header().Set(`Content-Type`, `application/x-www-form-urlencoded`)
	w.Header().Set(`Location`, r.FormValue(`redirect_uri`)+`?`+query.Encode())
	w.WriteHeader(http.StatusFound)
}

func authzNoHandler(w http.ResponseWriter, r *http.Request) {
	// OpenID Connect 3.1.2.6
	// Authentication Error Response
	query := url.Values{}
	query.Add(`error`, `access_denied`) // OAuth 2.0 4.1.2.1 Error Response Error Code
	w.Header().Set(`Content-Type`, `application/x-www-form-urlencoded`)
	w.Header().Set(`Location`, r.FormValue(`redirect_uri`)+`?`+query.Encode())
	w.WriteHeader(http.StatusFound)
}

// Access Token Endpoint
// OpenID Connect 3.1.3
// if production, you must use TLS, validates authorization code and should authenticates the client
func tokenHandler(w http.ResponseWriter, r *http.Request) {
	// OpenID Connect 3.1.3.3, 3.1.3.4
	w.Header().Set(`Content-Type`, `application/json`)
	w.Header().Set(`Cache-Control`, `no-store`)
	w.Header().Set(`Pragma`, `no-cache`)
	code := r.FormValue(`code`)
	if code != "authorizedyes" {
		// if the code is invalid, response Error
		// OpenID Connect 3.1.3.4
		w.WriteHeader(http.StatusBadRequest) // HTTP Response Code is 400
		// OAuth 2.0 5.2
		// REQUIRED Error Code
		w.Write([]byte(`{"error": "invalid_request"}`))
		return
	}
	// OpenID Connect 3.1.3.3
	w.Write([]byte(tokenJSON))
}

// scope parameter is string or list of string
// the request is OpenID Connect Request if the scope parameter is
// just "openid" string or contains "openid" in list
func isOpenIDConnect(scope string) bool {
	if scope == "" {
		return false
	}
	if scope == "openid" {
		return true
	}
	scopeList := strings.Split(scope, ",")
	if len(scopeList) < 2 {
		return false
	}
	for _, scope = range scopeList {
		if scope == "openid" {
			return true
		}
	}
	return false
}

// dummy authentication
func authenticate(userid, password string) bool {
	return userid == `userid` && password == `passwd`
}
