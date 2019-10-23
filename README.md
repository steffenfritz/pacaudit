[![Build Status](https://travis-ci.org/steffenfritz/pacaudit.svg?branch=master)](https://travis-ci.org/steffenfritz/pacaudit)
[![Go Report Card](https://goreportcard.com/badge/github.com/steffenfritz/pacaudit)](https://goreportcard.com/report/github.com/steffenfritz/pacaudit)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=steffenfritz_pacaudit&metric=alert_status)](https://sonarcloud.io/dashboard?id=steffenfritz_pacaudit)


# pacaudit

pacaudit audits installed packages on Arch Linux against known vulnerabilities listed on https://security.archlinux.org

# Installation

    trizen -S pacaudit

or

    yaourt -S pacaudit 

# Usage

1. pacaudit
    
    prints all vulnerable packages by name and the sum of all vulnerable packages


2. pacaudit -v
    
    prints all vulnerable packages by name, with CVE, severity and the sum of all vulnerable packages


3. pacaudit -n
    
    returns "OK" if no vulnerable packages are installed, "WARNING" if no vulnerable package with severity HIGH or higher is installed and CRITICAL else

    
4. pacaudit -c
    
    print results colorized. Used with verbose (-v) flag

5. pacaudit -h
   
   print usage and info
