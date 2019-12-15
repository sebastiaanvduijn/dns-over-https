package main

import (
	"database/sql"
	_ "github.com/go-sql-driver/mysql"
	"github.com/twinj/uuid"
	"log"
)

func (s *Server) CreateNewTokenRequestID(token string, name string, requesttype uint16) string {

	// create unique random ID
	uniqueID := uuid.NewV4().String()

	// open Database connection
	db, err := sql.Open("mysql", "api_user:password@/production")

	if err != nil {
		log.Fatal(err)
	}

	// prepare insert query
	stmtIns, err := db.Prepare("INSERT INTO `token_requests` ( `token`, `name`, `type`, `requestid`) VALUES( ?, ?, ?, ? )") // ? = placeholder
	if err != nil {
		log.Fatal(err)
	}
	defer stmtIns.Close() // Close the statement when we leave main() / the program terminates

	var tokenvalidationcount int
	// prepare query to check if token exist and if stats are enabled
	tokenvalidationqueryprep, err := db.Prepare("select COUNT(*) from `core_tokens` where `token` = ? AND `enable_stats` = ? ")
	tokenvalidationquery := tokenvalidationqueryprep.QueryRow(token, 1).Scan(&tokenvalidationcount)
	switch {
	case tokenvalidationquery != nil:
		log.Fatal(err)
	default:
		if tokenvalidationcount == 1 {
			// token is valid and stats are enabled, insert new entry and return request ID
			_, err = stmtIns.Exec(token, name, requesttype, uniqueID)
			if err != nil {
				panic(err.Error()) // proper error handling instead of panic in your app
			}
			defer db.Close()

			return uniqueID
		}
	}

	return "invalid_token"

}

func (s *Server) TokenBlackListCheck(token string, name string) string {

	db, err := sql.Open("mysql", "api_user:password@/production")

	if err != nil {
		log.Fatal(err)
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

	// token has been validated and inserted. Scan the blacklist to see if we need to block additional traffic

	var tokenblacklistusercount int
	tokenblacklistuserqueryprep, err := db.Prepare("SELECT COUNT(*) FROM `core_blacklist_users` where `name` = ? AND `token` = ?") // ? = placeholder

	tokenblacklistuserquery := tokenblacklistuserqueryprep.QueryRow(name, token).Scan(&tokenblacklistusercount)
	switch {
	case tokenblacklistuserquery != nil:
		log.Fatal(err)
	default:
		if tokenblacklistusercount == 1 {

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

			return "blackhole"
		}
	}

	// execute the query with accept for the stats

	return "true"

}

func (s *Server) DNSAnswerInsert(tokendnsrequestid string, answer string, count int, CustomDNSAnswer string) string {

	db, err := sql.Open("mysql", "api_user:password@/production")

	if err != nil {
		log.Fatal(err)
	}

	DNSAction := ""
	if CustomDNSAnswer == "blacklist" {
		DNSAction = "BLOCK"
	} else if CustomDNSAnswer == "proxyrequest" {
		DNSAction = "PROXIED"
	} else {
		DNSAction = "ALLOW"
	}

	// if token is validated and blacklist doesn't exist we can continue with the DNS request. Before exit register request in database

	// after token validation insert request into Database for tracking

	// Prepare statement for inserting data
	stmtIns, err := db.Prepare("insert into `token_answer` ( `answer`, `tokenrequestid`, `action`) values ( ?, ?, ?)") // ? = placeholder
	if err != nil {
		log.Fatal(err)
	}

	_, err = stmtIns.Exec(answer, tokendnsrequestid, DNSAction)
	if err != nil {
		log.Fatal(err)
	}

	defer stmtIns.Close() // Close the statement when we leave main() / the program terminates
	defer db.Close()

	return "true"

}
