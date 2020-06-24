package main

func checksinglepkg(pkgname *string, securityjson []byte) bool {

	vulnpkg := parse(securityjson)
	for _, v := range vulnpkg {
		for _, p := range v.Packages {
			if p == *pkgname {
				return true
			}
		}
	}

	return false
}
