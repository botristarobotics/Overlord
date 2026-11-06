// Copyright 2015 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/aitjcize/Overlord/overlord"
)

var bindAddr = flag.String("bind", "0.0.0.0", "specify alternate bind address")
var port = flag.Int("port", 0,
	"alternate port listen instead of standard ports (http:80, https:443)")
var lanDiscInterface = flag.String("lan-disc-iface", "",
	"the network interface used for broadcasting LAN discovery packets")
var noLanDisc = flag.Bool("no-lan-disc", false,
	"disable LAN discovery broadcasting")
var noAuth = flag.Bool("no-auth", false, "disable authentication")
var tlsCerts = flag.String("tls", "",
	"TLS certificates in the form of 'cert.pem,key.pem'. Empty to disable.")
var noLinkTLS = flag.Bool("no-link-tls", false,
	"disable TLS between ghost and overlord. Only valid when TLS is enabled.")
var htpasswdPath = flag.String("htpasswd-path", "app/overlord.htpasswd",
	"the path to the .htpasswd file.")
var cbAPIURL = flag.String("cb-api-url", "",
	"CloudBar API base URL (e.g. https://api.dev.botrista.io). Enables CloudBar login; htpasswd stays as fallback.")
var cbWebURL = flag.String("cb-web-url", "",
	"CloudBar web base URL used for the login redirect (e.g. https://cloudbar.dev.botrista.io).")

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: overlordd [OPTIONS]\n")
	flag.PrintDefaults()
	os.Exit(2)
}

func main() {
	flag.Usage = usage
	flag.Parse()
	if (*cbAPIURL == "") != (*cbWebURL == "") {
		fmt.Fprintln(os.Stderr, "-cb-api-url and -cb-web-url must be set together")
		os.Exit(2)
	}

	overlord.StartOverlord(*bindAddr, *port, *lanDiscInterface, !*noLanDisc,
		!*noAuth, *tlsCerts, !*noLinkTLS, *htpasswdPath, *cbAPIURL, *cbWebURL)
}
