//pacaudit audits installed packages against known vulnerabilities
//listed on security.archlinux.org/vulnerable. Use after pacman -Syu.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
)

// source url
const url string = "https://security.archlinux.org/vulnerable/json"

// flags
var nagios = flag.Bool("n", false, "run pacaudit as nagios plugin. If run in this mode it returns OK, WARNING or CRITICAL.")
var verbose = flag.Bool("v", false, "run pacaudit in verbose mode. This prints the severity and all related CVE.")

// issue struct.
type issue struct {
	Name       string   `json:"name"`
	Packages   []string `json:"packages"`
	Status     string   `json:"status"`
	Severity   string   `json:"severity"`
	Itype      string   `json:"type"`
	Affected   string   `json:"affected"`
	Fixed      string   `json:"fixed"`
	Ticket     string   `json:"ticket"`
	Issues     []string `json:"issues"`
	Advisories []string `json:"advisories"`
}

type output struct {
	Issues   string
	Severity string
	CVE      []string
}

// main function
func main() {
	flag.Parse()
	compare(parse(fetchrecent()), readDBContent(readDBPath()))
}

// compare installed package list with vulnerable package list
func compare(m []issue, locpkglist []string) {
	pkg_listed := make(map[string]bool)
	sev_warning := false
	sev_crit := false

	for _, entry := range m {
		for _, ipkgname := range entry.Packages {
			for _, lpkgname := range locpkglist {
				if strings.HasPrefix(lpkgname, ipkgname) {
					pkg_listed[lpkgname] = true
					if *verbose {
						fmt.Println("\n+ + +\n" + ipkgname + " is vulnerable.")
						fmt.Println("Severity: " + entry.Severity)
						fmt.Println("\nCVE:")
						for _, cve := range entry.Issues {
							fmt.Println(cve)
						}
					}

					if *nagios {
						if (entry.Severity == "Low") || (entry.Severity == "Medium") {
							sev_warning = true
						} else if (entry.Severity == "High") || (entry.Severity == "Critical") {
							sev_crit = true
						}
					}
				}
			}
		}
	}
	if *nagios {
		if sev_crit {
			fmt.Println("Critical")
			return
		} else if sev_warning {
			fmt.Println("Warning")
			return
		} else {
			fmt.Println("OK")
			return
		}
	}
	fmt.Println("\n" + strconv.Itoa(len(pkg_listed)) + " vulnerable package(s) installed.")
}

// a generic error check
func e(err error) {

	if err != nil {
		log.Fatal(err)
	}
}

// fetch recent vulnerable package list in json format
func fetchrecent() []byte {

	resp, err := http.Get(url)
	e(err)
	defer resp.Body.Close()

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

// get location of local pkg db
func readDBPath() string {

	var pkg_path string

	f, err := os.Open("/etc/pacman.conf")

	e(err)

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "DBPath") {
			pkg_path = string(scanner.Text())
		} else {
			pkg_path = "/var/lib/pacman/local"
		}
	}
	return pkg_path
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
