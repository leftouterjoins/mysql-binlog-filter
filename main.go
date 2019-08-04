package main

import (
	"database/sql"
	"fmt"
	_ "github.com/joshwbrick/mysql-binlog-filter/binlog"
)

func main() {
	conn, err := sql.Open("mysql-binlog", "config.json")
	if err != nil {
		fmt.Printf("Open Error: %+v\n", err)
	}

	err = conn.Ping()
	if err != nil {
		fmt.Printf("%+v\n", err)
	}
}
