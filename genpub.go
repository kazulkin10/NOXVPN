package main

import (
    "fmt"
    "io/ioutil"
    "golang.org/x/crypto/curve25519"
)

func main() {
    // SERVER
    srvPriv, _ := ioutil.ReadFile("/opt/nox/keys/server.key")
    srvPub, err := curve25519.X25519(srvPriv, curve25519.Basepoint)
    if err != nil {
        panic(err)
    }
    ioutil.WriteFile("/opt/nox/keys/server.pub", srvPub, 0644)

    // CLIENT
    cliPriv, _ := ioutil.ReadFile("/opt/nox/keys/client.key")
    cliPub, err := curve25519.X25519(cliPriv, curve25519.Basepoint)
    if err != nil {
        panic(err)
    }
    ioutil.WriteFile("/opt/nox/keys/client.pub", cliPub, 0644)

    fmt.Println("Generated server.pub and client.pub")
}
