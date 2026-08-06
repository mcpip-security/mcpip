// terraform-provider-mcpip manages authorization state on a self-hosted MCPIP gateway.
//
// Build and use it locally with a dev override — see integrations/terraform/README.md.
package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/mcpip-security/terraform-provider-mcpip/internal/provider"
)

// version is overwritten at build time: -ldflags "-X main.version=$(cat ../../VERSION)".
var version = "dev"

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "run with support for debuggers like delve")
	flag.Parse()

	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		Address: "registry.terraform.io/mcpip-security/mcpip",
		Debug:   debug,
	})
	if err != nil {
		log.Fatal(err)
	}
}
