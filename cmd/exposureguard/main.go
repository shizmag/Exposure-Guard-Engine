package main

import (
	_ "github.com/exposureguard/exposureguard/integrations/httpx"
	_ "github.com/exposureguard/exposureguard/integrations/katana"
	_ "github.com/exposureguard/exposureguard/integrations/nuclei"
	_ "github.com/exposureguard/exposureguard/integrations/subfinder"
	"github.com/exposureguard/exposureguard/internal/cli"
)

func main() {
	cli.Execute()
}
