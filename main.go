package main

import (
	"database/sql"
	"fmt"
	"os"

	_ "github.com/macinjosh/mysql-binlog-filter/binlog"
)

func main() {
	conn, err := sql.Open("mysql-binlog", "config.json")
	if err != nil {
		fmt.Printf("Open Error: %+v\n", err)
		os.Exit(1)
	}

	err = conn.Ping()
	if err != nil {
		fmt.Printf("%+v\n", err)
		os.Exit(1)
	}
}
