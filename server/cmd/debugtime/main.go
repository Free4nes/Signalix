package main

import (
    "database/sql"
    "fmt"
    "time"
    _ "github.com/lib/pq"
)

func main() {
    db, _ := sql.Open("postgres", "postgres://postgres:postgres@127.0.0.1:55432/messenger?sslmode=disable")
    defer db.Close()
    
    var t time.Time
    db.QueryRow("SELECT created_at FROM project_events LIMIT 1").Scan(&t)
    fmt.Printf("time: %v\n", t)
    fmt.Printf("RFC3339Nano: %s\n", t.UTC().Format(time.RFC3339Nano))
    fmt.Printf("RFC3339: %s\n", t.UTC().Format(time.RFC3339))
    fmt.Printf("Nanoseconds: %d\n", t.Nanosecond())
}
