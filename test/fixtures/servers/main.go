package main

import (
	"fmt"
	"net/http"
	"os"
)

func main() {
	address := ":8080"
	if len(os.Args) == 2 {
		address = os.Args[1]
	}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "dproxy-fixture") })
	if err := http.ListenAndServe(address, nil); err != nil {
		panic(err)
	}
}
