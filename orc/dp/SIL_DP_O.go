package main

import (
	"flag"
	"fmt"
	"os"
)

func usage() {
	fmt.Fprintf(os.Stderr,
		"Usage:\n"+
			"  SIL_DP_O --public <name>\n"+
			"  SIL_DP_O --private <name>\n"+
			"  SIL_DP_O --private-default\n")
}

func main() {
	var publicName string
	var privateName string
	var privateDefault bool

	flag.StringVar(&publicName, "public", "", "start public instance")
	flag.StringVar(&privateName, "private", "", "start private instance")
	flag.BoolVar(&privateDefault, "private-default", false, "start default private instance")
	flag.Parse()

	modes := 0
	if publicName != "" {
		modes++
	}
	if privateName != "" {
		modes++
	}
	if privateDefault {
		modes++
	}

	if modes != 1 {
		usage()
		os.Exit(ARG_FAULT)
	}

	visibility := "private"
	name := privateName

	switch {
	case publicName != "":
		visibility = "public"
		name = publicName
	case privateDefault:
		name = "default"
	}

	s, err := newServer(visibility, uint32(os.Getuid()), name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "SIL_DP_O: setup failed: %v\n", err)
		os.Exit(SYS_FAULT)
	}

	fmt.Printf("SIL_DP_O: instance=%s owner_uid=%d\n", s.instance, s.ownerUID)
	runServer(s)
}
