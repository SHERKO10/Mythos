// mythos-console — Console interactive Mythos C2
//
// Binaire séparé du team server.
// L'opérateur lance ce binaire sur sa machine pour interagir avec le C2.
//
// Usage :
//   ./mythos-console --api http://127.0.0.1:8443
//   ./mythos-console --api https://mon-c2.example.com:8443

package main

import (
	"flag"
	"fmt"

	"github.com/sherko/mythos-c2/server/operator"
)

func main() {
	api := flag.String("api", "http://127.0.0.1:8443", "URL de l'API Mythos C2")
	flag.Parse()

	fmt.Printf("[*] Connexion à %s...\n", *api)
	console := operator.NewConsole(*api)
	console.Run()
}
