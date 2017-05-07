[![Build Status](https://travis-ci.org/steffenfritz/pacaudit.svg?branch=master)](https://travis-ci.org/steffenfritz/pacaudit)


# pacaudit

pacaudit audits installed packages on Arch Linux against known vulnerabilities listed on https://security.archlinux.org

# Installation

1. gpg --recv-keys 7328F6E376924E4EE266381D3D9C808E038A615C

2. yaourt -S pacaudit

# Usage

1. pacaudit
    
    prints all vulnerable packages by name and the sum of all vulnerable packages


2. pacaudit -v
    
    prints all vulnerable packages by name, with CVE, severity and the sum of all vulnerable packages


3. pacaudit -n
    
    returns "OK" if no vulnerable packages are installed, "WARNING" if no vulnerable package with severity HIGH or higher is installed and CRITICAL else.
