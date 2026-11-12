// Command arc-mail-credential seals stdin for a current credential-key response.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/pavlith/arc/sdk/bootstrap"
	v1 "github.com/pavlith/arc/services/mail/api/v1"
	"github.com/pavlith/arc/services/mail/credentials"
)

func main() {
	path := flag.String("key-info", "", "path to the authenticated credentials/key JSON response")
	flag.Parse()
	if err := run(*path); err != nil {
		fmt.Fprintln(os.Stderr, "mail: credential sealing failed")
		os.Exit(1)
	}
}
func run(path string) error {
	var info v1.KeyInfo
	if err := bootstrap.ReadConfig(path, &info); err != nil {
		return err
	}
	password, err := credentials.ReadPassword(os.Stdin)
	if err != nil {
		return err
	}
	defer clear(password)
	sealed, err := credentials.Seal(info.PublicInfo, password)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"revision": info.Revision, "key_id": info.KeyID, "sealed": sealed})
}
