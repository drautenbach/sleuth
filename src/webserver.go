package main

import (
	"fmt"
	"net/http"
)

func WebServer() {
	http.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "it works!")
	})
	fs := http.FileServer(http.Dir("static/"))
	http.Handle("/", fs)

	http.ListenAndServe(":8080", nil)
}
