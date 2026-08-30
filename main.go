package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"text/template"
	"time"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type AuthData struct {
	Username      string
	RegisterError string
	SignInError   string
	ActiveTab     string
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

type SetUsernameData struct {
	GoogleID string
	Email    string
	Error    string
}

type GoogleUser struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

var db *sql.DB
var googleOAuthConfig *oauth2.Config

func initDB() {
	connStr := os.Getenv("DATABASE_URL")
	if connStr == "" {
		connStr = "host=localhost port=5432 user=notesuser password=yourpassword dbname=notesdb sslmode=disable"
	}

	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		panic(err)
	}

	if err = db.Ping(); err != nil {
		panic(err)
	}

	createTable := `CREATE TABLE IF NOT EXISTS users (
		id SERIAL PRIMARY KEY,
		username VARCHAR(25) UNIQUE,
		password TEXT,
		google_id TEXT UNIQUE,
		email TEXT
	);`

	_, err = db.Exec(createTable)
	if err != nil {
		panic(err)
	}

	createNotes := `CREATE TABLE IF NOT EXISTS notes (
		id SERIAL PRIMARY KEY,
		user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		title TEXT NOT NULL,
		content TEXT NOT NULL
	);`

	_, err = db.Exec(createNotes)
	if err != nil {
		panic(err)
	}
}

func initGoogleOAuth() {
	googleOAuthConfig = &oauth2.Config{
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		RedirectURL:  "https://notes-webapp-production-b92a.up.railway.app/auth/google/callback",
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}
}

func setUserCookie(w http.ResponseWriter, userID int) {
	http.SetCookie(w, &http.Cookie{
		Name:     "user_id",
		Value:    fmt.Sprintf("%d", userID),
		Path:     "/",
		MaxAge:   30 * 24 * 60 * 60,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(30 * 24 * time.Hour),
	})
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
	tmpl.Execute(w, AuthData{})
}

func Register(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("templates/manageAccount.html")
	if err != nil {
		http.Error(w, "Error Parsing File", http.StatusInternalServerError)
		return
	}

	if r.Method == "GET" {
		tmpl.Execute(w, AuthData{ActiveTab: "right-panel-active"})
		return
	}

	if r.Method == "POST" {
		r.ParseForm()

		username := r.FormValue("username")
		password := r.FormValue("password")
		confirmPassword := r.FormValue("password_confirm")

		renderError := func(msg string) {
			w.WriteHeader(http.StatusBadRequest)
			tmpl.Execute(w, AuthData{
				Username:      username,
				RegisterError: msg,
				ActiveTab:     "right-panel-active",
			})
		}

		if password != confirmPassword {
			renderError("Passwords do not match")
			return
		}
		if len(username) < 4 || len(username) > 25 {
			renderError("Username must be between 4 and 25 characters")
			return
		}
		if len(password) < 6 {
			renderError("Password must be a minimum of 6 characters")
			return
		}
		if password == username {
			renderError("Password cannot be the same as username")
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			renderError("Internal server error")
			return
		}

		var userID int
		err = db.QueryRow("INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id", username, string(hashedPassword)).Scan(&userID)
		if err != nil {
			renderError("Username already taken")
			return
		}

		setUserCookie(w, userID)
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
	}
}

func SignIn(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("templates/manageAccount.html")
	if err != nil {
		http.Error(w, "Error parsing file", http.StatusInternalServerError)
		return
	}

	if r.Method == "GET" {
		username := r.URL.Query().Get("username")
		tmpl.Execute(w, AuthData{Username: username})
		return
	}

	if r.Method == "POST" {
		r.ParseForm()

		username := r.FormValue("username")
		password := r.FormValue("password")

		var dbPassword sql.NullString
		var userID int

		err := db.QueryRow("SELECT id, password FROM users WHERE username = $1", username).Scan(&userID, &dbPassword)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			tmpl.Execute(w, AuthData{Username: username, SignInError: "Invalid username or password"})
			return
		}

		if !dbPassword.Valid || dbPassword.String == "" {
			w.WriteHeader(http.StatusUnauthorized)
			tmpl.Execute(w, AuthData{Username: username, SignInError: "This account uses Google Sign In"})
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(dbPassword.String), []byte(password))
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			tmpl.Execute(w, AuthData{Username: username, SignInError: "Invalid username or password"})
			return
		}

		setUserCookie(w, userID)
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
	}
}

// GoogleLogin redirects user to Google's consent screen
func GoogleLogin(w http.ResponseWriter, r *http.Request) {
	url := googleOAuthConfig.AuthCodeURL("state-token", oauth2.AccessTypeOnline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// GoogleCallback handles the response from Google after user consents
func GoogleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "No code returned from Google", http.StatusBadRequest)
		return
	}

	// Exchange code for token
	token, err := googleOAuthConfig.Exchange(r.Context(), code)
	if err != nil {
		http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
		return
	}

	// Fetch user info from Google
	client := googleOAuthConfig.Client(r.Context(), token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Failed to read user info", http.StatusInternalServerError)
		return
	}

	var googleUser GoogleUser
	if err := json.Unmarshal(body, &googleUser); err != nil {
		http.Error(w, "Failed to parse user info", http.StatusInternalServerError)
		return
	}

	// Check if this Google account already exists in our database
	var userID int
	err = db.QueryRow("SELECT id FROM users WHERE google_id = $1", googleUser.ID).Scan(&userID)
	if err == nil {
		// User exists — log them in directly
		setUserCookie(w, userID)
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	// New Google user — send them to pick a username
	http.Redirect(w, r, "/auth/set-username?google_id="+googleUser.ID+"&email="+googleUser.Email, http.StatusSeeOther)
}

// SetUsername serves the username picker page for new Google users
func SetUsername(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("templates/setUsername.html")
	if err != nil {
		http.Error(w, "Error parsing file", http.StatusInternalServerError)
		return
	}

	if r.Method == "GET" {
		googleID := r.URL.Query().Get("google_id")
		email := r.URL.Query().Get("email")
		tmpl.Execute(w, SetUsernameData{GoogleID: googleID, Email: email})
		return
	}

	if r.Method == "POST" {
		r.ParseForm()

		username := r.FormValue("username")
		googleID := r.FormValue("google_id")
		email := r.FormValue("email")

		renderError := func(msg string) {
			w.WriteHeader(http.StatusBadRequest)
			tmpl.Execute(w, SetUsernameData{GoogleID: googleID, Email: email, Error: msg})
		}

		if len(username) < 4 || len(username) > 25 {
			renderError("Username must be between 4 and 25 characters")
			return
		}

		var userID int
		err = db.QueryRow(
			"INSERT INTO users (username, google_id, email) VALUES ($1, $2, $3) RETURNING id",
			username, googleID, email,
		).Scan(&userID)
		if err != nil {
			renderError("Username already taken, please choose another")
			return
		}

		setUserCookie(w, userID)
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
	}
}

func DashBoard(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("user_id")
	if err != nil {
		http.Redirect(w, r, "/SignIn", http.StatusSeeOther)
		return
	}

	var username string
	err = db.QueryRow("SELECT username FROM users WHERE id = $1", cookie.Value).Scan(&username)
	if err != nil {
		http.Redirect(w, r, "/SignIn", http.StatusSeeOther)
		return
	}

	rows, err := db.Query("SELECT id, title, content FROM notes WHERE user_id = $1", cookie.Value)
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

	data := DashData{Username: username, Notes: notes}
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
		_, err = db.Exec("UPDATE notes SET title = $1, content = $2 WHERE id = $3 AND user_id = $4", title, content, noteID, cookie.Value)
		if err != nil {
			http.Error(w, "Error updating note: "+err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		_, err = db.Exec("INSERT INTO notes (user_id, title, content) VALUES ($1, $2, $3)", cookie.Value, title, content)
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

	idStr := strings.TrimPrefix(r.URL.Path, "/note/")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "Invalid note ID", http.StatusBadRequest)
		return
	}

	err = db.QueryRow("SELECT id, title, content FROM notes WHERE user_id = $1 AND id = $2", cookie.Value, id).Scan(&activeNote.ID, &activeNote.Title, &activeNote.Content)
	if err != nil {
		http.Error(w, "Error fetching note", http.StatusInternalServerError)
		return
	}

	var username string
	db.QueryRow("SELECT username FROM users WHERE id = $1", cookie.Value).Scan(&username)

	rows, err := db.Query("SELECT id, title, content FROM notes WHERE user_id = $1", cookie.Value)
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
	cookie, err := r.Cookie("user_id")
	if err != nil {
		http.Redirect(w, r, "/SignIn", http.StatusSeeOther)
		return
	}

	idStr := strings.TrimPrefix(r.URL.Path, "/deletenote/")
	id, err := strconv.Atoi(idStr)
	if err == nil {
		db.Exec("DELETE FROM notes WHERE id = $1 AND user_id = $2", id, cookie.Value)
	}

	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func Logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "user_id",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
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
	initDB()
	initGoogleOAuth()

	http.HandleFunc("/", Home)
	http.HandleFunc("/register", Register)
	http.HandleFunc("/SignIn", SignIn)
	http.HandleFunc("/dashboard", DashBoard)
	http.HandleFunc("/savenote", SaveNote)
	http.HandleFunc("/note/", ViewNote)
	http.HandleFunc("/deletenote/", DeleteNote)
	http.HandleFunc("/logout", Logout)
	http.HandleFunc("/UnavailableFeatures", UnavailableFeatures)

	// Google OAuth routes
	http.HandleFunc("/auth/google/login", GoogleLogin)
	http.HandleFunc("/auth/google/callback", GoogleCallback)
	http.HandleFunc("/auth/set-username", SetUsername)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	fmt.Printf("Server starting on port %s\n", port)
	http.ListenAndServe(":"+port, nil)
}
