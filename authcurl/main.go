package main

import (
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/mailgun/httpsign"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <keypath> <URL>\n", os.Args[0])
		os.Exit(1)
	}

	svc, err := httpsign.New(&httpsign.Config{
		Keypath:        os.Args[1],
		SignVerbAndURI: true,
	})
	checkErr(err)

	req, err := http.NewRequest("GET", os.Args[2], nil)
	checkErr(err)

	err = svc.SignRequest(req)
	checkErr(err)

	resp, err := http.DefaultClient.Do(req)
	checkErr(err)

	defer resp.Body.Close()
	io.Copy(os.Stdout, resp.Body)
}

func checkErr(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
