package main

import (
	"github.com/exposureguard/exposureguard/integrations"
	"github.com/exposureguard/exposureguard/internal/cli"
)

func main() {
	integrations.InitDefaultRegistry()
	cli.Execute()
}
