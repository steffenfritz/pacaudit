package main

import (
	"bufio"
	"fmt"
	. "github.com/logrusorgru/aurora"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
)

// compare installed package list with vulnerable package list
func compare(m []issue, locpkglist []string, w *tabwriter.Writer) {
	pkgListed := make(map[string]bool)
	sevWarning := false
	sevCrit := false

	for _, entry := range m {
		for _, ipkgname := range entry.Packages {
			for _, lpkgname := range locpkglist {
				if strings.HasPrefix(lpkgname, ipkgname+"-"+entry.Affected) {
					pkgListed[lpkgname] = true
					if *verbose {
						cveTemp := entry.Issues[0]
						for _, cve := range entry.Issues[1:] {
							cveTemp += "\t" + cve
						}
						if *color {
							if entry.Severity == "Critical" {
								fmt.Fprintln(w, Magenta(lpkgname+"\t"+entry.Severity+"\t"+cveTemp))
							} else if entry.Severity == "High" {
								fmt.Fprintln(w, Red(lpkgname+"\t"+entry.Severity+"\t"+cveTemp))
							} else if entry.Severity == "Medium" {
								fmt.Fprintln(w, Brown(lpkgname+"\t"+entry.Severity+"\t"+cveTemp))
							} else {
								fmt.Fprintln(w, Green(lpkgname+"\t"+entry.Severity+"\t"+cveTemp))
							}
						} else {
							fmt.Fprintln(w, lpkgname+"\t"+entry.Severity+"\t"+cveTemp)
						}

					}

					if *nagios {
						if (entry.Severity == "Low") || (entry.Severity == "Medium") {
							sevWarning = true
						} else if (entry.Severity == "High") || (entry.Severity == "Critical") {
							sevCrit = true
						}
					}
				}
			}
		}
	}
	w.Flush()
	if *nagios {
		if sevCrit {
			fmt.Println("Critical")
			return
		} else if sevWarning {
			fmt.Println("Warning")
			return
		} else {
			fmt.Println("OK")
			return
		}
	}
	if !*verbose {
		for val := range pkgListed {
			fmt.Println(val)
		}
	}
	fmt.Println("\n" + strconv.Itoa(len(pkgListed)) + " vulnerable package(s) installed.\n")
}

// get location of local pkg db
func readDBPath() string {

	var pkgPath string

	f, err := os.Open("/etc/pacman.conf")

	e(err)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "DBPath") {
			pkgPath = string(scanner.Text())
		} else {
			pkgPath = "/var/lib/pacman/local"
		}
	}
	return pkgPath
}

// get local pkg list
func readDBContent(dbPath string) []string {

	var pkgList []string
	entries, err := ioutil.ReadDir(dbPath)

	e(err)

	for _, g := range entries {
		pkgList = append(pkgList, g.Name())
	}

	return pkgList
}
