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

func logMiddleware(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf(`REQUEST: %s`, r.URL)
		h.ServeHTTP(w, r)
	})
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(indexHTML))
}

func authzHandler(w http.ResponseWriter, r *http.Request) {
	query := url.Values{}
	query.Add(`scope`, `openid`)
	query.Add(`response_type`, `code`)
	query.Add(`client_id`, `client application`)
	query.Add(`redirect_uri`, `http://localhost:8000/callback`)
	w.Header().Set(`Location`, `http://localhost:8080/authorize?`+query.Encode())
	w.WriteHeader(http.StatusFound)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue(`code`)
	if code == "" {
		w.Write([]byte(fmt.Sprintf(`<html><body>Error: %s</body></html>`, r.FormValue(`error`))))
	}
	form := url.Values{}
	form.Add(`grant_type`, `authorization_code`)
	form.Add(`code`, code)
	form.Add(`redirect_uri`, `http://localhost:8000/callback`)
	buf := bytes.Buffer{}
	buf.WriteString(form.Encode())
	// in production, you must use https
	resp, _ := http.Post(`http://localhost:8080/token`, `application/x-www-form-urlencoded`, &buf)
	// you must validate response id token in production
	tokenb, _ := ioutil.ReadAll(resp.Body)
	token := string(tokenb)

	w.Write([]byte(fmt.Sprintf(callbackHTML, token)))
}
