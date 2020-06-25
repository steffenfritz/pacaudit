package main

import (
	"io/ioutil"
)

func getofflinejson(filename string) error {
	err := ioutil.WriteFile(filename, fetchrecent(), 0644)
	return err
}
