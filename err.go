package main

import "log"

// a generic error check
func e(err error) {

	if err != nil {
		log.Fatal(err)
	}
}
