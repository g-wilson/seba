package seba

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/ioutil"
)

//go:embed clients.json
var fs embed.FS

const filepath = "clients.json"

var Clients = mustReadClients()

var ClientsByID = arrangeClients(Clients)

func mustReadClients() []Client {
	file, err := fs.Open(filepath)
	if err != nil {
		panic(fmt.Errorf("cannot open client config file at %s: %w", filepath, err))
	}

	body, err := ioutil.ReadAll(file)
	if err != nil {
		panic(fmt.Errorf("cannot read client config file at %s: %w", filepath, err))
	}

	cls := []Client{}
	err = json.Unmarshal(body, &cls)
	if err != nil {
		panic(fmt.Errorf("cannot decode client config file at %s: %w", filepath, err))
	}

	return cls
}

func arrangeClients(list []Client) map[string]Client {
	arr := map[string]Client{}

	for _, cl := range list {
		arr[cl.ID] = cl
	}

	return arr
}
