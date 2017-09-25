package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
)

const (
	iss       = "https://localhost:8000"
	indexHTML = `<html>
<body>
<a href="/authz">Start AuthZ</a>
</body>
</html>`
	callbackHTML = `<html>
<body>
token: %s
</body>
</html>`
)

func main() { os.Exit(exec()) }

// main logic
func exec() int {
	// binding routes
	http.Handle(`/`, logMiddleware(indexHandler))
	http.Handle(`/authz`, logMiddleware(authzHandler))
	http.Handle(`/callback`, logMiddleware(callbackHandler))

	// run http server
	if err := http.ListenAndServe(":8000", nil); err != nil {
		log.Printf("%s", err)
		return 1
	}

	return 0
}

// http handling middleware for logging
func logMiddleware(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf(`REQUEST: %s`, r.URL)
		h.ServeHTTP(w, r)
	})
}

// top page
func indexHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(indexHTML))
}

// OAuth 2.0 Authorization Request
// OpenID Connect Authentication Request
func authzHandler(w http.ResponseWriter, r *http.Request) {
	// OpenID Connect 3.1.2.1
	query := url.Values{}
	query.Add(`scope`, `openid`)                                // REQUIRED parameter
	query.Add(`response_type`, `code`)                          // REQUIRED parameter
	query.Add(`client_id`, `client application`)                // REQUIRED parameter
	query.Add(`redirect_uri`, `http://localhost:8000/callback`) // REQUIRED parameter
	// Redirect to OpenID Connect Provider (Authorization Server)
	w.Header().Set(`Location`, `http://localhost:8080/authorize?`+query.Encode())
	w.WriteHeader(http.StatusFound)
}

// Redirect Callback endpoint
// called back when the authorization/authentication process is done
func callbackHandler(w http.ResponseWriter, r *http.Request) {
	// check the code
	code := r.FormValue(`code`)
	if code == "" {
		// if there is no code parameter, the result of authZ/authN process is errored
		w.Write([]byte(fmt.Sprintf(`<html><body>Error: %s</body></html>`, r.FormValue(`error`))))
		return
	}
	// OpenID Connect 3.1.3.1
	// Access Token Request
	// may be required basic/other client authentication
	form := url.Values{}
	form.Add(`grant_type`, `authorization_code`)               // REQUIRED parameter
	form.Add(`code`, code)                                     // REQUIRED parameter, given authorize code
	form.Add(`redirect_uri`, `http://localhost:8000/callback`) // OPTIONAL parameter
	buf := bytes.Buffer{}
	buf.WriteString(form.Encode())
	// in production, you must use TLS, client authentication
	resp, _ := http.Post(`http://localhost:8080/token`, `application/x-www-form-urlencoded`, &buf)
	// you must validate response id token in production
	// OpenID Connect 3.1.3.7
	tokenb, _ := ioutil.ReadAll(resp.Body)
	token := string(tokenb)

	w.Write([]byte(fmt.Sprintf(callbackHTML, token)))
}
