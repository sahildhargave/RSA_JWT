package main

import (
	"log"
	"rsa/db"
	"rsa/server"

	"rsa/server/middleware/jwt"
)

var host = "localhost"
var port = "9090"

func main() {
	db.InitDB()

	jwtErr := jwt.InitJWT()
	if jwtErr != nil {
		log.Println("Error initializing the JWT!")
		log.Fatal(jwtErr)
	}

	serverErr := server.StartServer(host, port)

	if serverErr != nil {
		log.Println("Error starting server!")
		log.Fatal(serverErr)
	}

}
