package main

func checksinglepkg(pkgname *string) bool {

	vulnpkg := parse(fetchrecent())
	for _, v := range vulnpkg {
		for _, p := range v.Packages {
			if p == *pkgname {
				return true
			}
		}
	}

	return false
}
