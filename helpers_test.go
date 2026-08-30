package main

import (
	"html/template"
	"testing"
)

func TestHelpers(t *testing.T) {
	imgFile := NoteFile{FileName: "photo.PNG", FileType: "image/png"}
	if !isImage(imgFile) {
		t.Errorf("Expected isImage to be true for photo.PNG")
	}

	vidFile := NoteFile{FileName: "clip.mp4", FileType: "video/mp4"}
	if !isVideo(vidFile) {
		t.Errorf("Expected isVideo to be true for clip.mp4")
	}

	audFile := NoteFile{FileName: "song.mp3", FileType: "audio/mpeg"}
	if !isAudio(audFile) {
		t.Errorf("Expected isAudio to be true for song.mp3")
	}

	sanitized := sanitizeFileName("My file (1) #test?.png")
	if sanitized != "My_file__1___test_.png" {
		t.Errorf("Unexpected sanitized filename: %s", sanitized)
	}
}

func TestTemplateParsing(t *testing.T) {
	tmpl, err := template.New("DashBoard.html").Funcs(funcMap).ParseFiles("templates/DashBoard.html")
	if err != nil {
		t.Fatalf("Failed to parse DashBoard.html: %v", err)
	}
	if tmpl == nil {
		t.Fatal("Parsed template is nil")
	}
}
