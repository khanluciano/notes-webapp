package main

import (
	"bytes"
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
	Files   []NoteFile
}

type NoteFile struct {
	ID       int
	FileURL  string
	FileName string
	FileType string
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
var funcMap = template.FuncMap{
	"contains": strings.Contains,
}

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

	createFiles := `CREATE TABLE IF NOT EXISTS note_files (
		id SERIAL PRIMARY KEY,
		note_id INTEGER REFERENCES notes(id) ON DELETE CASCADE,
		user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
		file_url TEXT NOT NULL,
		file_name TEXT NOT NULL,
		file_type TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT NOW()
	);`
	_, err = db.Exec(createFiles)
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

// uploadToSupabase uploads a file to Supabase Storage and returns the public URL
func uploadToSupabase(fileBytes []byte, fileName string, contentType string) (string, error) {
	supabaseURL := os.Getenv("SUPABASE_URL")
	supabaseKey := os.Getenv("SUPABASE_KEY")
	bucket := "note-files"

	// Build the upload URL
	uploadURL := fmt.Sprintf("%s/storage/v1/object/%s/%s", supabaseURL, bucket, fileName)

	req, err := http.NewRequest("POST", uploadURL, bytes.NewReader(fileBytes))
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+supabaseKey)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("x-upsert", "true") // overwrite if same name exists

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("supabase upload failed status %d: %s", resp.StatusCode, string(body))
	}
	// Build the public URL
	publicURL := fmt.Sprintf("%s/storage/v1/object/public/%s/%s", supabaseURL, bucket, fileName)
	return publicURL, nil
}

// fetchNoteFiles fetches all files attached to a note
func fetchNoteFiles(noteID int) []NoteFile {
	rows, err := db.Query("SELECT id, file_url, file_name, file_type FROM note_files WHERE note_id = $1", noteID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var files []NoteFile
	for rows.Next() {
		var f NoteFile
		rows.Scan(&f.ID, &f.FileURL, &f.FileName, &f.FileType)
		files = append(files, f)
	}
	return files
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

func GoogleLogin(w http.ResponseWriter, r *http.Request) {
	url := googleOAuthConfig.AuthCodeURL("state-token", oauth2.AccessTypeOnline)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func GoogleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "No code returned from Google", http.StatusBadRequest)
		return
	}

	token, err := googleOAuthConfig.Exchange(r.Context(), code)
	if err != nil {
		http.Error(w, "Failed to exchange token", http.StatusInternalServerError)
		return
	}

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

	var userID int
	err = db.QueryRow("SELECT id FROM users WHERE google_id = $1", googleUser.ID).Scan(&userID)
	if err == nil {
		setUserCookie(w, userID)
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	http.Redirect(w, r, "/auth/set-username?google_id="+googleUser.ID+"&email="+googleUser.Email, http.StatusSeeOther)
}

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
	tmpl, err := template.New("DashBoard.html").Funcs(funcMap).ParseFiles("templates/DashBoard.html")
	if err != nil {
		http.Error(w, "Error parsing template", http.StatusInternalServerError)
		return
	}
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

	// Parse multipart form — 20MB max
	r.ParseMultipartForm(30 << 20)
	fmt.Printf("MultipartForm: %v\n", r.MultipartForm)
	fmt.Printf("Form files: %v\n", r.MultipartForm)
	if r.MultipartForm != nil {
		fmt.Printf("Files in form: %v\n", r.MultipartForm.File)
	}
	title := r.FormValue("title")
	content := r.FormValue("note")
	noteID := r.FormValue("note_id")

	if title == "" {
		title = "Untitled note"
	}

	var savedNoteID int

	if noteID != "" && noteID != "0" {
		_, err = db.Exec("UPDATE notes SET title = $1, content = $2 WHERE id = $3 AND user_id = $4", title, content, noteID, cookie.Value)
		if err != nil {
			http.Error(w, "Error updating note: "+err.Error(), http.StatusInternalServerError)
			return
		}
		savedNoteID, _ = strconv.Atoi(noteID)
	} else {
		err = db.QueryRow("INSERT INTO notes (user_id, title, content) VALUES ($1, $2, $3) RETURNING id", cookie.Value, title, content).Scan(&savedNoteID)
		if err != nil {
			http.Error(w, "Error saving note: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// Handle file uploads if any
	if r.MultipartForm != nil && r.MultipartForm.File != nil {
		files := r.MultipartForm.File["files"]
		for _, fileHeader := range files {
			// Check file size — 10MB per file
			if fileHeader.Size > 10<<20 {
				continue
			}

			file, err := fileHeader.Open()
			if err != nil {
				continue
			}
			defer file.Close()

			fileBytes, err := io.ReadAll(file)
			if err != nil {
				continue
			}

			contentType := fileHeader.Header.Get("Content-Type")
			fileName := fmt.Sprintf("%d-%d-%s", savedNoteID, time.Now().UnixNano(), fileHeader.Filename)
			publicURL, err := uploadToSupabase(fileBytes, fileName, contentType)
			if err != nil {
				fmt.Printf("Upload error: %v\n", err)
				continue
			}

			fmt.Printf("Uploaded to: %s\n", publicURL)

			_, dbErr := db.Exec(
				"INSERT INTO note_files (note_id, user_id, file_url, file_name, file_type) VALUES ($1, $2, $3, $4, $5)",
				savedNoteID, cookie.Value, publicURL, fileHeader.Filename, contentType,
			)
			if dbErr != nil {
				fmt.Printf("DB insert error: %v\n", dbErr)
			}
		}
	}

	http.Redirect(w, r, fmt.Sprintf("/note/%d", savedNoteID), http.StatusSeeOther)
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

	// Fetch files for this note
	activeNote.Files = fetchNoteFiles(activeNote.ID)

	fmt.Printf("Files for note %d: %+v\n", activeNote.ID, activeNote.Files)

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
	tmpl, err := template.New("DashBoard.html").Funcs(funcMap).ParseFiles("templates/DashBoard.html")
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

func DeleteFile(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("user_id")
	if err != nil {
		http.Redirect(w, r, "/SignIn", http.StatusSeeOther)
		return
	}

	idStr := strings.TrimPrefix(r.URL.Path, "/deletefile/")
	parts := strings.SplitN(idStr, "/", 2)
	if len(parts) != 2 {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	fileID, err := strconv.Atoi(parts[0])
	noteID := parts[1]

	if err == nil {
		db.Exec("DELETE FROM note_files WHERE id = $1 AND user_id = $2", fileID, cookie.Value)
	}

	http.Redirect(w, r, "/note/"+noteID, http.StatusSeeOther)
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
	http.HandleFunc("/deletefile/", DeleteFile)
	http.HandleFunc("/logout", Logout)
	http.HandleFunc("/UnavailableFeatures", UnavailableFeatures)
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
