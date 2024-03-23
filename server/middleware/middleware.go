package middleware

import (
	"log"
	"net/http"
	"time"

	"github.com/justinas/alice"
)

func NewHandler() http.Handler {
	return alice.New(recoverHandler, authHandler).ThenFunc(logicHandler)

}

func logicHandler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "restricted":
	case "/login":
		switch r.Method {
		case "GET":
		case "POST":
		default:

		}
	case "register":
		switch r.Method {
		case "GET":
		case "POST":
		default:
		}
	case "/logout":
	case "/deleteUser":
	default:
	}
}
func recoverHandler(next http.Handler) http.Handler {
	//😎😍😘🥰 catch any errors and return an internal server error to the client
	fn := func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Panic("Recovered! Panic: %+v", err)
				http.Error(w, http.StatusText(500), 500)
			}
		}()

		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func authHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/restricted", "logout", "/deleteUser":
		default:
		}
	}
}

func nullifyTokenCookies(w *http.Response, r *http.Request) {
	authCookie := http.Cookie{
		Name:    "AuthToken",
		Value:   "",
		Expires: time.Now().Add(-1000 * time.Hour),
	}
}

func setAuthAndRefreshCookies() {

}

func grabCsrfFromReq(r *http.Request) string {

}
