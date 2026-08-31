package main

import (
	"bytes"
	"html/template"
	"strings"
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

func TestMediaKindMatches(t *testing.T) {
	cases := []struct {
		kind string
		file NoteFile
		want bool
	}{
		{"image", NoteFile{FileName: "a.png", FileType: "image/png"}, true},
		{"image", NoteFile{FileName: "a.mp3", FileType: "audio/mpeg"}, false},
		{"video", NoteFile{FileName: "a.mp4", FileType: "video/mp4"}, true},
		{"audio", NoteFile{FileName: "a.wav", FileType: "audio/wav"}, true},
		{"document", NoteFile{FileName: "a.pdf", FileType: "application/pdf"}, false},
	}
	for _, c := range cases {
		if got := mediaKindMatches(c.kind, c.file); got != c.want {
			t.Errorf("mediaKindMatches(%q, %q) = %v, want %v", c.kind, c.file.FileName, got, c.want)
		}
	}
}

func TestSanitizeNoteHTMLKeepsMediaBlocks(t *testing.T) {
	in := `<div class="media-block" contenteditable="false" data-media="image" ` +
		`data-file-url="https://cdn.example.com/a.png" data-file-id="12">` +
		`<img src="https://cdn.example.com/a.png" alt="a" loading="lazy" />` +
		`</div><div class="media-caret"><br /></div>Hello`

	out := sanitizeNoteHTML(in)

	for _, want := range []string{
		`class="media-block"`,
		`data-media="image"`,
		`data-file-id="12"`,
		`src="https://cdn.example.com/a.png"`,
		`Hello`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("sanitized output missing %q:\n%s", want, out)
		}
	}
}

func TestSanitizeNoteHTMLStripsDangerousMarkup(t *testing.T) {
	cases := []string{
		`<script>alert(1)</script>`,
		`<img src="javascript:alert(1)">`,
		`<img src=x onerror="alert(1)">`,
		`<div onclick="alert(1)">hi</div>`,
		`<iframe src="https://evil.example"></iframe>`,
		`<a href="javascript:alert(1)">x</a>`,
		`<video src="data:text/html,<script>alert(1)</script>"></video>`,
	}

	for _, in := range cases {
		out := sanitizeNoteHTML(in)
		lower := strings.ToLower(out)
		if strings.Contains(lower, "<script") || strings.Contains(lower, "<iframe") || strings.Contains(lower, "<a ") {
			t.Errorf("disallowed tag survived sanitizing %q -> %q", in, out)
		}
		// Live attributes only: escaped text such as `href=&#34;javascript:` is
		// inert, so the checks target real (unescaped) attribute syntax.
		for _, bad := range []string{`onerror=`, `onclick=`, `="javascript:`, `="data:`} {
			if strings.Contains(lower, bad) {
				t.Errorf("unsafe attribute %q survived sanitizing %q -> %q", bad, in, out)
			}
		}
	}
}

func TestSanitizeNoteHTMLIsIdempotent(t *testing.T) {
	in := `<div class="media-block"><img src="https://cdn.example.com/a.png" alt="a & b" /></div>plain <b>text</b>`
	once := sanitizeNoteHTML(in)
	twice := sanitizeNoteHTML(once)
	if once != twice {
		t.Errorf("sanitizeNoteHTML not idempotent:\nonce:  %s\ntwice: %s", once, twice)
	}
}

func TestPreviewText(t *testing.T) {
	got := previewText(`<div class="media-block"><img src="https://x/a.png"></div><p>Hello&nbsp;there</p>`)
	if strings.Contains(got, "<") || strings.Contains(got, "img") {
		t.Errorf("previewText should be plaintext, got %q", got)
	}
	if !strings.Contains(got, "Hello") || !strings.Contains(got, "there") {
		t.Errorf("previewText dropped visible text, got %q", got)
	}

	long := previewText(strings.Repeat("word ", 100))
	if len([]rune(long)) > 141 {
		t.Errorf("previewText not truncated, length %d", len([]rune(long)))
	}
}

func TestDashboardRendersMediaBlock(t *testing.T) {
	tmpl, err := template.New("DashBoard.html").Funcs(funcMap).ParseFiles("templates/DashBoard.html")
	if err != nil {
		t.Fatalf("Failed to parse DashBoard.html: %v", err)
	}

	data := DashData{
		Username: "tester",
		ActiveNote: Note{
			ID:    7,
			Title: "With media",
			Content: `<div class="media-block" contenteditable="false" data-media="audio" ` +
				`data-file-url="https://cdn.example.com/s.mp3">` +
				`<audio src="https://cdn.example.com/s.mp3" controls preload="metadata"></audio>` +
				`</div><div class="media-caret"><br /></div>notes`,
		},
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		t.Fatalf("Failed to render dashboard: %v", err)
	}

	out := buf.String()
	for _, want := range []string{
		`id="note-editor"`,
		`id="insert-menu"`,
		`Insert Audio`,
		`Insert Image`,
		`Insert Video`,
		`class="media-block"`,
		`https://cdn.example.com/s.mp3`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered dashboard missing %q", want)
		}
	}
}
