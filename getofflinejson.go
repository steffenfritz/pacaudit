package main

import (
	"io/ioutil"
)

// write downloaded info into a json file with timestamped file name
func getofflinejson(filename string) error {
	err := ioutil.WriteFile(filename, fetchrecent(), 0644)
	return err
}
