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

	// Prepare statement for TOKEN validation
	tokenvalidationquery, err := db.Prepare("SELECT * FROM `core_tokens` where `token` = ?")
	if err != nil {
		panic(err.Error()) // proper error handling instead of panic in your app
	}
	defer tokenvalidationquery.Close()

	// Check if the token exist in the database if not quit and don't return a message
	// Execute the query
	tokenvalidationcount := 0
	tokenvalidationquery.QueryRow(token).Scan(&tokenvalidationcount)

	if tokenvalidationcount == 0 {
		return false
	}

	// after token validation insert request into Database for tracking

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

	// token has been validated and inserted. Scan the blacklist to see if we need to block additional traffic

	// Prepare statement for TOKEN blacklist check
	tokenblacklistcheck, err := db.Prepare("SELECT * FROM `core_blacklist` where `name` = ? AND `token` = ?")
	if err != nil {
		panic(err.Error()) // proper error handling instead of panic in your app
	}
	defer tokenblacklistcheck.Close()

	// Execute the query
	tokenblacklistcheckcount := 0
	tokenblacklistcheck.QueryRow(name, token).Scan(&tokenblacklistcheckcount)

	if tokenblacklistcheckcount == 1 {
		return false
	}

	// if token is validated and blacklist doesn't exist we can continue with the DNS request

	return true

}
