package main

import (
	"database/sql"
	_ "github.com/go-sql-driver/mysql"
	"log"
)

func (s *Server) TokenNameValidation(token string, name string) string {

	db, err := sql.Open("mysql", "api_user:password@/production")

	if err != nil {
		panic(err.Error()) // Just for example purpose. You should use proper error handling instead of panic
	}

	var tokenvalidationcount int
	tokenvalidationqueryprep, err := db.Prepare("SELECT COUNT(*) FROM `core_tokens` where `token` = ?") // ? = placeholder

	tokenvalidationquery := tokenvalidationqueryprep.QueryRow(token).Scan(&tokenvalidationcount)
	switch {
	case tokenvalidationquery != nil:
		log.Fatal(err)
	default:
		if tokenvalidationcount == 0 {
			return "invalid_token"
		}
	}

	// if token is validated and blacklist doesn't exist we can continue with the DNS request. Before exit register request in database

	// after token validation insert request into Database for tracking

	// Prepare statement for inserting data
	stmtIns, err := db.Prepare("INSERT INTO `token_requests` ( `token`, `name`, `action`) VALUES( ?, ?, ? )") // ? = placeholder
	if err != nil {
		panic(err.Error()) // proper error handling instead of panic in your app
	}
	defer stmtIns.Close() // Close the statement when we leave main() / the program terminates

	// token has been validated and inserted. Scan the blacklist to see if we need to block additional traffic

	var tokenblacklistusercount int
	tokenblacklistuserqueryprep, err := db.Prepare("SELECT COUNT(*) FROM `core_blacklist_users` where `name` = ? AND `token` = ?") // ? = placeholder

	tokenblacklistuserquery := tokenblacklistuserqueryprep.QueryRow(name, token).Scan(&tokenblacklistusercount)
	switch {
	case tokenblacklistuserquery != nil:
		log.Fatal(err)
	default:
		if tokenblacklistusercount == 1 {

			_, err = stmtIns.Exec(token, name, "block")
			if err != nil {
				panic(err.Error()) // proper error handling instead of panic in your app
			}
			defer db.Close()

			return "blackhole"
		}
	}

	// check global blacklist enabled for user

	var tokenblacklistglobalcount int
	tokenblacklistglobalqueryprep, err := db.Prepare("SELECT COUNT(*) FROM core_tokens INNER JOIN token_blacklist_membership ON core_tokens.id = token_blacklist_membership.tokenid INNER JOIN core_blacklist_global ON token_blacklist_membership.blacklist = core_blacklist_global.blacklist_id WHERE core_tokens.token = ? AND core_blacklist_global.url = ?") // ? = placeholder

	tokenblacklistglobalquery := tokenblacklistglobalqueryprep.QueryRow(token, name).Scan(&tokenblacklistglobalcount)
	switch {
	case tokenblacklistglobalquery != nil:
		log.Fatal(err)
	default:
		if tokenblacklistglobalcount == 1 {

			_, err = stmtIns.Exec(token, name, "block")
			if err != nil {
				panic(err.Error()) // proper error handling instead of panic in your app
			}
			defer db.Close()

			return "blackhole"
		}
	}

	// execute the query with accept for the stats

	_, err = stmtIns.Exec(token, name, "accept")
	if err != nil {
		panic(err.Error()) // proper error handling instead of panic in your app
	}
	defer db.Close()

	return "true"

}

func (s *Server) DNSAnswerInsert(token string, answer string) string {

	db, err := sql.Open("mysql", "api_user:password@/production")

	if err != nil {
		panic(err.Error()) // Just for example purpose. You should use proper error handling instead of panic
	}

	// if token is validated and blacklist doesn't exist we can continue with the DNS request. Before exit register request in database

	// after token validation insert request into Database for tracking

	// Prepare statement for inserting data
	stmtIns, err := db.Prepare("INSERT INTO `test` ( `token`, `input`) VALUES( ?, ?)") // ? = placeholder
	if err != nil {
		panic(err.Error()) // proper error handling instead of panic in your app
	}

	_, err = stmtIns.Exec(token, answer)
	if err != nil {
		panic(err.Error()) // proper error handling instead of panic in your app
	}

	defer stmtIns.Close() // Close the statement when we leave main() / the program terminates
	defer db.Close()

	return "true"

}
