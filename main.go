//pacaudit audits installed packages against known vulnerabilities
//listed on security.archlinux.org/vulnerable. Use after pacman -Syu.
package main

import (
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
)

// source url
const url string = "https://security.archlinux.org/vulnerable/json"

// version
const version string = "v1.1.1"

// flags
var nagios = flag.Bool("n", false, "run pacaudit as nagios plugin. If run in this mode it returns OK, WARNING or CRITICAL.")
var verbose = flag.Bool("v", false, "run pacaudit in verbose mode. This prints the severity and all related CVE.")
var color = flag.Bool("c", false, "print results colorized when used with verbose flag.")
var singlepkg = flag.String("p", "", "check if provided package name is listed as vulnerable. Useful for pacman hooks.")

// main function
func main() {
	flag.Usage = func() {
		fmt.Println(`		
pacaudit v1.1.0 Copyright (C) 2017  Steffen Fritz

This program comes with ABSOLUTELY NO WARRANTY
This is free software, and you are welcome to redistribute it
under certain conditions; GNU General Public License v3.0`)

		fmt.Println()

		flag.PrintDefaults()

		fmt.Println()
	}
	w := tabwriter.NewWriter(os.Stdout, 1, 0, 1, ' ', tabwriter.Debug)
	flag.Parse()

	if len(*singlepkg) != 0 {
		vulnerable := checksinglepkg(singlepkg)
		if vulnerable {

			fmt.Println("!!! WARNING: " + *singlepkg + " is vulnerable !!!")

		}
		return
	}

	compare(parse(fetchrecent()), readDBContent(readDBPath()), w)
}
