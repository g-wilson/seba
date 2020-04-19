package app

type Client struct {
	ID                       string
	InviteConsumptionEnabled bool
	EmailAuthenticationURL   string
	DefaultScopes            []string
}

var clients = []Client{
	Client{
		ID:                       "client_52842f21-d9fd-4201-b198-c5f0585cb3be",
		EmailAuthenticationURL:   "https://localhost:8080/authenticate",
		InviteConsumptionEnabled: true,
		DefaultScopes:            []string{"api"},
	},
}

var apiGatewayClient = "client_awsapigateway"

var clientsByID = arrangeClients()

func arrangeClients() map[string]Client {
	arr := map[string]Client{}

	for _, cl := range clients {
		arr[cl.ID] = cl
	}

	return arr
}
