package main

import (
	"database/sql"
	_ "github.com/go-sql-driver/mysql"
)

func (s *Server) TokenNameValidation(token string, name string) bool {

	db, err := sql.Open("mysql", "api_user:password@/production")

	if err != nil {
		panic(err.Error()) // Just for example purpose. You should use proper error handling instead of panic
	}

	// Prepare statement for inserting data
	stmtIns, err := db.Prepare("INSERT INTO `token_requests` ( `token`, `name`) VALUES( ?, ? )") // ? = placeholder
	if err != nil {
		panic(err.Error()) // proper error handling instead of panic in your app
	}
	defer stmtIns.Close() // Close the statement when we leave main() / the program terminates

	// execute the query

	_, err = stmtIns.Exec(token, name) // Insert tuples (i, i^2)
	if err != nil {
		panic(err.Error()) // proper error handling instead of panic in your app
	}
	defer db.Close()

	return true

}
