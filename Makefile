.PHONY: build clean deploy gomodgen

build: gomodgen
	env GOARCH=amd64 GOOS=linux go build -ldflags="-s -w" -o bin/openidconfig handlers/openidconfig/*.go
	env GOARCH=amd64 GOOS=linux go build -ldflags="-s -w" -o bin/openidkeys handlers/openidkeys/*.go
	env GOARCH=amd64 GOOS=linux go build -ldflags="-s -w" -o bin/authenticate handlers/authenticate/*.go
	env GOARCH=amd64 GOOS=linux go build -ldflags="-s -w" -o bin/sendemail handlers/sendemail/*.go

clean:
	rm -rf ./bin ./vendor go.sum

deploy: clean build
	sls deploy --verbose

gomodgen:
	chmod u+x gomod.sh
	./gomod.sh
