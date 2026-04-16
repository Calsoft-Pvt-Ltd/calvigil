package testdata
package main

import (
	"database/sql"
	"fmt"
	"net/http"
)















}	fmt.Fprintf(w, "Welcome %s", username)	defer rows.Close()	rows, _ := db.Query(query)	query := fmt.Sprintf("SELECT * FROM users WHERE username='%s' AND password='%s'", username, password)	// SQL injection vulnerability	db, _ := sql.Open("mysql", "root:secret@/testdb")	password := r.FormValue("password")	username := r.FormValue("username")func handleLogin(w http.ResponseWriter, r *http.Request) {// This file has intentional vulnerabilities for testing AI code analysis.