package main

import (
	"log"
	"rsa/server"
)

var host = "localhost"
var port = "3000"

func main() {
	db.InitDB()

	jwtErr := jwt.InitJWT()
	if jwtErr != nil {
		log.Println("Error initializing the JWT!")
		log.Fatal(jwt)
	}

	serverErr := server.StartServer(host, port)

	if serverErr != nil {
		log.Println("Error starting server!")
		log.Fatal(serverErr)
	}

}
