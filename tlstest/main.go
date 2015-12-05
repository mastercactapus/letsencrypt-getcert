package main

import (
	"io"
	"net/http"
)

func ServeHTTP(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, "Hello World!")
}

func main() {
	http.ListenAndServeTLS(":443", "acmetest.crt", "acmetest.key", http.HandlerFunc(ServeHTTP))
}
