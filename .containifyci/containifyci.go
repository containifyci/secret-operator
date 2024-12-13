//go:generate bash -c "if [ ! -f go.mod ]; then echo 'Initializing go.mod...'; go mod init .containifyci; else echo 'go.mod already exists. Skipping initialization.'; fi"
//go:generate go get github.com/containifyci/engine-ci/protos2
//go:generate go get github.com/containifyci/engine-ci/client
//go:generate go mod tidy

package main

import (
	"os"

	"github.com/containifyci/engine-ci/client/pkg/build"
	"github.com/containifyci/engine-ci/protos2"
)

func registryAuth() map[string]*protos2.ContainerRegistry {
	return map[string]*protos2.ContainerRegistry{
		"docker.io": {
			Username: "env:DOCKER_USER",
			Password: "env:DOCKER_TOKEN",
		},
		"ghcr.io": {
			Username: "USERNAME",
			Password: "env:GHCR_TOKEN",
		},
	}
}

func main() {
	os.Chdir("../")
	client := build.NewGoServiceBuild("secret-operator-client")
	client.Image = ""
	client.File = "cmd/client/main.go"

	server := build.NewGoServiceBuild("secret-operator-server")
	server.File = "cmd/server/main.go"
	server.Properties = map[string]*build.ListValue{
		"goreleaser": build.NewList("true"),
	}
	server.Registries = registryAuth()
	build.BuildAsync(client, server)
}
