package main

import (
	"database/sql"
	"fmt"
	_ "github.com/macinjosh/mysql-binlog-filter/binlog"
)

func main() {
	conn, err := sql.Open("mysql-binlog", "{\"host\": \"127.0.0.1\", \"port\": 3306, \"user\": \"root\", \"password\": \"root\", \"database\": \"information_schema\", \"ssl\": false}")
	if err != nil {
		fmt.Printf("Open Error: %+v\n", err)
	}

	err = conn.Ping()
	if err != nil {
		fmt.Printf("Ping Error: %+v\n", err)
	}
}
