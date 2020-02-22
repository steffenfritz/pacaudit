package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
)

// fetch recent vulnerable package list in json format
func fetchrecent() []byte {

	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	e(err)

	req.Header.Set("User-Agent", "Pacaudit/v1.1.2")

	resp, err := client.Do(req)
	e(err)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Fatal("Could not connect to https://security.archlinux.org")
	}

	body, err := ioutil.ReadAll(resp.Body)

	return body
}

// unmarshal json into list of type issue
func parse(body []byte) []issue {

	var m []issue
	err := json.Unmarshal(body, &m)
	e(err)
	return m
}
