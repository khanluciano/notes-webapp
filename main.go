package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"html/template"
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

func isImage(f NoteFile) bool {
	ft := strings.ToLower(f.FileType)
	fn := strings.ToLower(f.FileName)
	return strings.Contains(ft, "image") ||
		strings.HasSuffix(fn, ".png") || strings.HasSuffix(fn, ".jpg") ||
		strings.HasSuffix(fn, ".jpeg") || strings.HasSuffix(fn, ".gif") ||
		strings.HasSuffix(fn, ".webp") || strings.HasSuffix(fn, ".svg") ||
		strings.HasSuffix(fn, ".bmp") || strings.HasSuffix(fn, ".ico")
}

func isVideo(f NoteFile) bool {
	ft := strings.ToLower(f.FileType)
	fn := strings.ToLower(f.FileName)
	return strings.Contains(ft, "video") ||
		strings.HasSuffix(fn, ".mp4") || strings.HasSuffix(fn, ".webm") ||
		strings.HasSuffix(fn, ".ogg") || strings.HasSuffix(fn, ".mov") ||
		strings.HasSuffix(fn, ".mkv") || strings.HasSuffix(fn, ".avi")
}

func isAudio(f NoteFile) bool {
	ft := strings.ToLower(f.FileType)
	fn := strings.ToLower(f.FileName)
	return strings.Contains(ft, "audio") ||
		strings.HasSuffix(fn, ".mp3") || strings.HasSuffix(fn, ".wav") ||
		strings.HasSuffix(fn, ".ogg") || strings.HasSuffix(fn, ".m4a") ||
		strings.HasSuffix(fn, ".flac") || strings.HasSuffix(fn, ".aac")
}

var funcMap = template.FuncMap{
	"contains": strings.Contains,
	"isImage":  isImage,
	"isVideo":  isVideo,
	"isAudio":  isAudio,
}

func initDB() {
	connStr := os.Getenv("DATABASE_URL")
	if connStr == "" {
		connStr = "host=localhost port=5432 user=notesuser password=yourpassword dbname=notesdb sslmode=disable"
	}

	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Failed to open DB: %v", err)
	}

	if err = db.Ping(); err != nil {
		log.Printf("⚠️ Warning: DB ping failed on startup (will retry on requests): %v", err)
	} else {
		log.Println("✅ Database connection established")
	}

	createTable := `CREATE TABLE IF NOT EXISTS users (
		id SERIAL PRIMARY KEY,
		username VARCHAR(25) UNIQUE,
		password TEXT,
		google_id TEXT UNIQUE,
		email TEXT
	);`
	if _, err = db.Exec(createTable); err != nil {
		log.Printf("Error creating users table: %v", err)
	}

	createNotes := `CREATE TABLE IF NOT EXISTS notes (
		id SERIAL PRIMARY KEY,
		user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		title TEXT NOT NULL,
		content TEXT NOT NULL
	);`
	if _, err = db.Exec(createNotes); err != nil {
		log.Printf("Error creating notes table: %v", err)
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
	if _, err = db.Exec(createFiles); err != nil {
		log.Printf("Error creating note_files table: %v", err)
	}
}

func initGoogleOAuth() {
	redirectURL := os.Getenv("GOOGLE_REDIRECT_URL")
	if redirectURL == "" {
		if appURL := os.Getenv("APP_URL"); appURL != "" {
			redirectURL = strings.TrimRight(appURL, "/") + "/auth/google/callback"
		} else if railwayDomain := os.Getenv("RAILWAY_PUBLIC_DOMAIN"); railwayDomain != "" {
			redirectURL = "https://" + railwayDomain + "/auth/google/callback"
		} else {
			redirectURL = "https://notes-webapp-production-b92a.up.railway.app/auth/google/callback"
		}
	}

	googleOAuthConfig = &oauth2.Config{
		ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
		ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
		RedirectURL:  redirectURL,
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

func getSupabaseURL() string {
	raw := strings.TrimSpace(os.Getenv("SUPABASE_URL"))
	if raw == "" {
		return ""
	}
	raw = strings.TrimRight(raw, "/")
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		raw = "https://" + raw
	}
	return raw
}

func getSupabaseKey() string {
	key := os.Getenv("SUPABASE_KEY")
	if key == "" {
		key = os.Getenv("SUPABASE_SERVICE_ROLE_KEY")
	}
	if key == "" {
		key = os.Getenv("SUPABASE_ANON_KEY")
	}
	return strings.TrimSpace(key)
}

func getSupabaseBucket() string {
	bucket := strings.TrimSpace(os.Getenv("SUPABASE_BUCKET"))
	if bucket == "" {
		bucket = "note-files"
	}
	return bucket
}

func sanitizeFileName(name string) string {
	var b strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	cleaned := b.String()
	if cleaned == "" || cleaned == "." {
		cleaned = "file"
	}
	return cleaned
}

// ensureSupabaseBucket checks if the bucket exists in Supabase and creates it as public if missing
func ensureSupabaseBucket() {
	supabaseURL := getSupabaseURL()
	supabaseKey := getSupabaseKey()
	bucket := getSupabaseBucket()

	if supabaseURL == "" || supabaseKey == "" {
		log.Println("⚠️  Supabase URL or Key not set. Skipping bucket check.")
		return
	}

	checkURL := fmt.Sprintf("%s/storage/v1/bucket/%s", supabaseURL, bucket)
	req, err := http.NewRequest("GET", checkURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("apikey", supabaseKey)
	req.Header.Set("Authorization", "Bearer "+supabaseKey)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			log.Printf("✅ Supabase bucket '%s' is verified and accessible\n", bucket)
			return
		}
	}

	// Try creating the public bucket if not found
	createURL := fmt.Sprintf("%s/storage/v1/bucket", supabaseURL)
	payload := map[string]interface{}{
		"id":     bucket,
		"name":   bucket,
		"public": true,
	}
	bodyJSON, _ := json.Marshal(payload)
	createReq, err := http.NewRequest("POST", createURL, bytes.NewReader(bodyJSON))
	if err != nil {
		return
	}
	createReq.Header.Set("apikey", supabaseKey)
	createReq.Header.Set("Authorization", "Bearer "+supabaseKey)
	createReq.Header.Set("Content-Type", "application/json")

	createResp, err := client.Do(createReq)
	if err == nil {
		defer createResp.Body.Close()
		respBytes, _ := io.ReadAll(createResp.Body)
		if createResp.StatusCode == http.StatusOK || createResp.StatusCode == http.StatusCreated {
			log.Printf("✅ Automatically created public Supabase bucket '%s'\n", bucket)
		} else {
			log.Printf("ℹ️  Supabase bucket check/create response (%d): %s\n", createResp.StatusCode, string(respBytes))
		}
	}
}

// uploadToSupabase uploads a file to Supabase Storage and returns the public URL
func uploadToSupabase(fileBytes []byte, fileName string, contentType string) (string, error) {
	supabaseURL := getSupabaseURL()
	supabaseKey := getSupabaseKey()
	bucket := getSupabaseBucket()

	if supabaseURL == "" || supabaseKey == "" {
		return "", fmt.Errorf("SUPABASE_URL or SUPABASE_KEY environment variable is not set")
	}

	if contentType == "" || contentType == "application/octet-stream" {
		contentType = http.DetectContentType(fileBytes)
	}

	uploadURL := fmt.Sprintf("%s/storage/v1/object/%s/%s", supabaseURL, bucket, fileName)
	log.Printf("[Supabase] Uploading to: %s (ContentType: %s, Size: %d bytes)\n", uploadURL, contentType, len(fileBytes))

	req, err := http.NewRequest("POST", uploadURL, bytes.NewReader(fileBytes))
	if err != nil {
		return "", err
	}

	req.Header.Set("apikey", supabaseKey)
	req.Header.Set("Authorization", "Bearer "+supabaseKey)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("x-upsert", "true")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("supabase HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("supabase upload failed with status %d: %s", resp.StatusCode, string(body))
	}

	publicURL := fmt.Sprintf("%s/storage/v1/object/public/%s/%s", supabaseURL, bucket, fileName)
	log.Printf("[Supabase] Upload success! Public URL: %s\n", publicURL)
	return publicURL, nil
}

// deleteFromSupabase removes an object from Supabase Storage
func deleteFromSupabase(fileURL string) {
	supabaseURL := getSupabaseURL()
	supabaseKey := getSupabaseKey()
	bucket := getSupabaseBucket()

	if supabaseURL == "" || supabaseKey == "" || fileURL == "" {
		return
	}

	prefix := fmt.Sprintf("/storage/v1/object/public/%s/", bucket)
	idx := strings.Index(fileURL, prefix)
	var fileName string
	if idx != -1 {
		fileName = fileURL[idx+len(prefix):]
	} else {
		fileName = filepath.Base(fileURL)
	}

	deleteURL := fmt.Sprintf("%s/storage/v1/object/%s/%s", supabaseURL, bucket, fileName)
	req, err := http.NewRequest("DELETE", deleteURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("apikey", supabaseKey)
	req.Header.Set("Authorization", "Bearer "+supabaseKey)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err == nil {
		resp.Body.Close()
	}
}

// fetchNoteFiles fetches all files attached to a note
func fetchNoteFiles(noteID int) []NoteFile {
	rows, err := db.Query("SELECT id, file_url, file_name, file_type FROM note_files WHERE note_id = $1 ORDER BY id ASC", noteID)
	if err != nil {
		log.Printf("Error fetching files for note %d: %v", noteID, err)
		return nil
	}
	defer rows.Close()

	var files []NoteFile
	for rows.Next() {
		var f NoteFile
		if err := rows.Scan(&f.ID, &f.FileURL, &f.FileName, &f.FileType); err == nil {
			files = append(files, f)
		}
	}
	return files
}

func Home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	// Redirect to dashboard if already authenticated
	if cookie, err := r.Cookie("user_id"); err == nil && cookie.Value != "" {
		var exists int
		if err := db.QueryRow("SELECT 1 FROM users WHERE id = $1", cookie.Value).Scan(&exists); err == nil && exists == 1 {
			http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
			return
		}
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
		if cookie, err := r.Cookie("user_id"); err == nil && cookie.Value != "" {
			var exists int
			if err := db.QueryRow("SELECT 1 FROM users WHERE id = $1", cookie.Value).Scan(&exists); err == nil && exists == 1 {
				http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
				return
			}
		}
		tmpl.Execute(w, AuthData{ActiveTab: "right-panel-active"})
		return
	}

	if r.Method == "POST" {
		r.ParseForm()

		username := strings.TrimSpace(r.FormValue("username"))
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
		if cookie, err := r.Cookie("user_id"); err == nil && cookie.Value != "" {
			var exists int
			if err := db.QueryRow("SELECT 1 FROM users WHERE id = $1", cookie.Value).Scan(&exists); err == nil && exists == 1 {
				http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
				return
			}
		}
		username := r.URL.Query().Get("username")
		tmpl.Execute(w, AuthData{Username: username})
		return
	}

	if r.Method == "POST" {
		r.ParseForm()

		username := strings.TrimSpace(r.FormValue("username"))
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
		log.Printf("Google OAuth exchange error: %v", err)
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

		username := strings.TrimSpace(r.FormValue("username"))
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

	rows, err := db.Query("SELECT id, title, content FROM notes WHERE user_id = $1 ORDER BY id DESC", cookie.Value)
	if err != nil {
		http.Error(w, "Error fetching notes", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var notes []Note
	for rows.Next() {
		var n Note
		if err := rows.Scan(&n.ID, &n.Title, &n.Content); err == nil {
			notes = append(notes, n)
		}
	}

	data := DashData{Username: username, Notes: notes}
	tmpl, err := template.New("DashBoard.html").Funcs(funcMap).ParseFiles("templates/DashBoard.html")
	if err != nil {
		http.Error(w, "Error parsing template: "+err.Error(), http.StatusInternalServerError)
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

	// Parse multipart form — 32MB max
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		r.ParseForm()
	}

	title := strings.TrimSpace(r.FormValue("title"))
	content := r.FormValue("note")
	noteID := strings.TrimSpace(r.FormValue("note_id"))

	if title == "" {
		title = "Untitled note"
	}

	var savedNoteID int

	if noteID != "" && noteID != "0" {
		id, err := strconv.Atoi(noteID)
		if err == nil {
			_, err = db.Exec("UPDATE notes SET title = $1, content = $2 WHERE id = $3 AND user_id = $4", title, content, id, cookie.Value)
			if err != nil {
				http.Error(w, "Error updating note: "+err.Error(), http.StatusInternalServerError)
				return
			}
			savedNoteID = id
		}
	}

	if savedNoteID == 0 {
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
			if fileHeader == nil || fileHeader.Filename == "" || fileHeader.Size == 0 {
				continue
			}

			// Check file size — max 30MB per file
			if fileHeader.Size > 30<<20 {
				log.Printf("File '%s' exceeds max size of 30MB, skipping", fileHeader.Filename)
				continue
			}

			file, err := fileHeader.Open()
			if err != nil {
				log.Printf("Error opening uploaded file '%s': %v", fileHeader.Filename, err)
				continue
			}

			fileBytes, err := io.ReadAll(file)
			file.Close()
			if err != nil {
				log.Printf("Error reading uploaded file '%s': %v", fileHeader.Filename, err)
				continue
			}

			contentType := fileHeader.Header.Get("Content-Type")
			if contentType == "" || contentType == "application/octet-stream" {
				contentType = http.DetectContentType(fileBytes)
			}

			cleanName := sanitizeFileName(filepath.Base(fileHeader.Filename))
			fileName := fmt.Sprintf("%d_%d_%s", savedNoteID, time.Now().UnixNano(), cleanName)

			publicURL, err := uploadToSupabase(fileBytes, fileName, contentType)
			if err != nil {
				log.Printf("Upload error for '%s': %v", fileHeader.Filename, err)
				continue
			}

			log.Printf("Uploaded '%s' -> %s", fileHeader.Filename, publicURL)

			_, dbErr := db.Exec(
				"INSERT INTO note_files (note_id, user_id, file_url, file_name, file_type) VALUES ($1, $2, $3, $4, $5)",
				savedNoteID, cookie.Value, publicURL, fileHeader.Filename, contentType,
			)
			if dbErr != nil {
				log.Printf("DB insert error for file '%s': %v", fileHeader.Filename, dbErr)
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
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	err = db.QueryRow("SELECT id, title, content FROM notes WHERE user_id = $1 AND id = $2", cookie.Value, id).Scan(&activeNote.ID, &activeNote.Title, &activeNote.Content)
	if err != nil {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}

	// Fetch files for this note
	activeNote.Files = fetchNoteFiles(activeNote.ID)

	var username string
	db.QueryRow("SELECT username FROM users WHERE id = $1", cookie.Value).Scan(&username)

	rows, err := db.Query("SELECT id, title, content FROM notes WHERE user_id = $1 ORDER BY id DESC", cookie.Value)
	if err != nil {
		http.Error(w, "Error fetching notes", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var notes []Note
	for rows.Next() {
		var n Note
		if err := rows.Scan(&n.ID, &n.Title, &n.Content); err == nil {
			notes = append(notes, n)
		}
	}

	data := DashData{
		Username:   username,
		Notes:      notes,
		ActiveNote: activeNote,
	}
	tmpl, err := template.New("DashBoard.html").Funcs(funcMap).ParseFiles("templates/DashBoard.html")
	if err != nil {
		http.Error(w, "Error parsing template: "+err.Error(), http.StatusInternalServerError)
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
		// Clean up files in Supabase storage
		rows, fErr := db.Query("SELECT file_url FROM note_files WHERE note_id = $1 AND user_id = $2", id, cookie.Value)
		if fErr == nil {
			for rows.Next() {
				var fURL string
				if scanErr := rows.Scan(&fURL); scanErr == nil && fURL != "" {
					deleteFromSupabase(fURL)
				}
			}
			rows.Close()
		}
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
		var fileURL string
		db.QueryRow("SELECT file_url FROM note_files WHERE id = $1 AND user_id = $2", fileID, cookie.Value).Scan(&fileURL)
		if fileURL != "" {
			deleteFromSupabase(fileURL)
		}
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
	ensureSupabaseBucket()

	// Diagnostic status logs for environment configuration
	log.Println("--- Environment Configuration Status ---")
	if os.Getenv("DATABASE_URL") == "" {
		log.Println("ℹ️  DATABASE_URL not set, using default local postgres fallback")
	} else {
		log.Println("✅ DATABASE_URL is configured")
	}

	if getSupabaseURL() == "" {
		log.Println("⚠️  SUPABASE_URL is NOT set — file uploads to storage will fail!")
	} else {
		log.Printf("✅ SUPABASE_URL configured: %s\n", getSupabaseURL())
	}

	if getSupabaseKey() == "" {
		log.Println("⚠️  SUPABASE_KEY is NOT set — file uploads to storage will fail!")
	} else {
		log.Println("✅ SUPABASE_KEY is configured")
	}

	log.Printf("✅ SUPABASE_BUCKET is set to: %s\n", getSupabaseBucket())
	log.Println("----------------------------------------")

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

	log.Printf("Server starting on port %s...\n", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Server stopped with error: %v", err)
	}
}
