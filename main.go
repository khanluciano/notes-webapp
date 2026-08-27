package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"text/template"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

type Name struct {
	Username string
}

type LoginData struct {
	Username string
}

type Note struct {
	ID      int
	Title   string
	Content string
}

type DashData struct {
	Username   string
	Notes      []Note
	ActiveNote Note
}

var db *sql.DB
var welcomemsg Name

func initBD() {
	var err error
	db, err = sql.Open("sqlite3", "./users.db")
	if err != nil {
		panic(err)
	}

	createTable := `CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password TEXT NOT NULL
	);`

	_, err = db.Exec(createTable)
	if err != nil {
		panic(err)
	}

	createNotes := `CREATE TABLE IF NOT EXISTS notes (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		title TEXT NOT NULL,
		content TEXT NOT NULL
	);`

	_, err = db.Exec(createNotes)
	if err != nil {
		panic(err)
	}
}

func Home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	tmpl, err := template.ParseFiles("templates/manageAccount.html")
	if err != nil {
		http.Error(w, "Error Parsing File", http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, nil)
}

func Register(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		tmpl, err := template.ParseFiles("templates/createAccount.html")
		if err != nil {
			http.Error(w, "Error Parsing File", http.StatusBadRequest)
			return
		}
		tmpl.Execute(w, nil)
		return
	}

	if r.Method == "POST" {
		r.ParseForm()

		username := r.FormValue("username")
		password := r.FormValue("password")
		confirmPassword := r.FormValue("password_confirm")

		if password != confirmPassword {
			http.Error(w, "Passwords do not match", http.StatusBadRequest)
			return
		}

		if len(username) < 4 || len(username) > 15 {
			http.Error(w, "Username must be between 4 and 15 characters", http.StatusBadRequest)
			return
		}
		if len(password) < 6 {
			http.Error(w, "Password must be at least 6 characters", http.StatusBadRequest)
			return
		}
		if password == username {
			http.Error(w, "Password cannot be the same as username", http.StatusBadRequest)
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		_, err = db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", username, string(hashedPassword))
		if err != nil {
			http.Error(w, "Username already taken or database error", http.StatusBadRequest)
			return
		}

		http.Redirect(w, r, "/SignIn?username="+username, http.StatusSeeOther)
	}
}

func SignIn(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		username := r.URL.Query().Get("username")
		tmpl, err := template.ParseFiles("templates/manageAccount.html")
		if err != nil {
			http.Error(w, "Error parsing file: "+err.Error(), http.StatusInternalServerError)
			return
		}
		tmpl.Execute(w, LoginData{Username: username})
	}
	if r.Method == "POST" {
		r.ParseForm()

		username := r.FormValue("username")
		password := r.FormValue("password")

		var dbPassword string
		var userID int

		err := db.QueryRow("SELECT id, password FROM users WHERE username = ?", username).Scan(&userID, &dbPassword)
		if err != nil {
			fmt.Fprintln(w, "Invalid username or password")
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(dbPassword), []byte(password))
		if err != nil {
			fmt.Fprintln(w, "Invalid username or password")
			return
		}

		welcomemsg = Name{Username: username}

		http.SetCookie(w, &http.Cookie{
			Name:  "user_id",
			Value: fmt.Sprintf("%d", userID),
			Path:  "/",
		})

		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
	}
}

func DashBoard(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("user_id")
	if err != nil {
		http.Redirect(w, r, "/SignIn", http.StatusSeeOther)
		return
	}

	rows, err := db.Query("SELECT id, title, content FROM notes WHERE user_id = ?", cookie.Value)
	if err != nil {
		http.Error(w, "Error fetching notes", http.StatusInternalServerError)
		return
	}

	defer rows.Close()

	var notes []Note
	for rows.Next() {
		var n Note
		rows.Scan(&n.ID, &n.Title, &n.Content)
		notes = append(notes, n)
	}

	data := DashData{Username: welcomemsg.Username, Notes: notes}
	tmpl, _ := template.ParseFiles("templates/DashBoard.html")
	tmpl.Execute(w, data)
}

func SaveNote(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}
	cookie, err := r.Cookie("user_id")

	if err != nil {
		http.Redirect(w, r, "/SignIn", http.StatusSeeOther)
		return
	}

	r.ParseForm()

	title := r.FormValue("title")
	content := r.FormValue("note")
	noteID := r.FormValue("note_id")

	if title == "" {
		title = "Untitled note"
	}

	if noteID != "" && noteID != "0" {
		_, err = db.Exec("UPDATE notes SET title = ?, content = ? WHERE id = ?", title, content, noteID)
		if err != nil {
			http.Error(w, "Error updating note: "+err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		_, err = db.Exec("INSERT INTO notes (user_id, title, content) VALUES (?, ?, ?)", cookie.Value, title, content)
		if err != nil {
			http.Error(w, "Error saving note: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func ViewNote(w http.ResponseWriter, r *http.Request) {
	var activeNote Note
	cookie, err := r.Cookie("user_id")
	if err != nil {
		http.Redirect(w, r, "/SignIn", http.StatusSeeOther)
		return
	}
	// r.URL.Path gives you the full path e.g. "/note/123"
	// TrimPrefix strips "/note/" leaving just "123"
	idStr := strings.TrimPrefix(r.URL.Path, "/note/")
	id, err := strconv.Atoi(idStr)

	err = db.QueryRow("SELECT id, title, content FROM notes WHERE user_id = ? AND id = ?", cookie.Value, id).Scan(&activeNote.ID, &activeNote.Title, &activeNote.Content)
	if err != nil {
		http.Error(w, "Error fetching note", http.StatusInternalServerError)
		return
	}

	var username string
	db.QueryRow("SELECT username FROM users WHERE id = ?", cookie.Value).Scan(&username)

	rows, err := db.Query("SELECT id, title, content FROM notes WHERE user_id = ?", cookie.Value)
	if err != nil {
		http.Error(w, "Error fetching notes", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var notes []Note
	for rows.Next() {
		var n Note
		rows.Scan(&n.ID, &n.Title, &n.Content)
		notes = append(notes, n)
	}
	data := DashData{
		Username:   username,
		Notes:      notes,
		ActiveNote: activeNote,
	}
	tmpl, err := template.ParseFiles("templates/DashBoard.html")
	if err != nil {
		http.Error(w, "Error parsing template", http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, data)

}

func DeleteNote(w http.ResponseWriter, r *http.Request) {
	idStr := strings.TrimPrefix(r.URL.Path, "/deletenote/")
	id, _ := strconv.Atoi(idStr)
	db.Exec("DELETE FROM notes WHERE id = ?", id)
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func Logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:   "user_id",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
	welcomemsg = Name{}
	http.Redirect(w, r, "/SignIn", http.StatusSeeOther)
}

func UnavailableFeatures(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("templates/Comingsoon.html")
	if err != nil {
		http.Error(w, "Error Parsing File", http.StatusBadRequest)
		return
	}
	tmpl.Execute(w, nil)
}

func main() {
	initBD()
	http.HandleFunc("/", Home)
	http.HandleFunc("/register", Register)
	http.HandleFunc("/SignIn", SignIn)
	http.HandleFunc("/dashboard", DashBoard)
	http.HandleFunc("/savenote", SaveNote)
	http.HandleFunc("/note/", ViewNote)
	http.HandleFunc("/deletenote/", DeleteNote)
	http.HandleFunc("/logout", Logout)
	http.HandleFunc("/UnavailableFeatures", UnavailableFeatures)
	fmt.Println("Server starting at http://localhost:8080")
	http.ListenAndServe(":8080", nil)
}
