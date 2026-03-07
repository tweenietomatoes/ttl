package crypto

import "testing"

func TestSanitizeFilename(t *testing.T) {
	cases := []struct {
		input, expected string
	}{
		{"../../etc/passwd", "passwd"},
		{".hidden", "hidden"},
		{"", "download.bin"},
		{".", "download.bin"},
		{"path/to/file.txt", "file.txt"},
		{"back\\slash\\file.txt", "file.txt"},
		{"normal.pdf", "normal.pdf"},
		{"hello\x00world.txt", "helloworld.txt"},
		{"new\nline.txt", "newline.txt"},
		{"\x01\x02\x03", "download.bin"},
		{"tab\there.txt", "tabhere.txt"},

		// Windows-invalid characters
		{"file:stream.txt", "filestream.txt"},
		{"what*.log", "what.log"},
		{"who?.doc", "who.doc"},
		{"say\"hello\".txt", "sayhello.txt"},
		{"a<b>c|d.bin", "abcd.bin"},

		// Trailing dots and spaces (Windows trims these silently)
		{"file.txt.", "file.txt"},
		{"file.txt...", "file.txt"},
		{"file.txt   ", "file.txt"},
		{"file.txt . ", "file.txt"},

		// Windows reserved device names
		{"CON", "_CON"},
		{"con", "_con"},
		{"PRN.txt", "_PRN.txt"},
		{"nul.tar.gz", "_nul.tar.gz"},
		{"com1.log", "_com1.log"},
		{"LPT3", "_LPT3"},
		{"AUX.pdf", "_AUX.pdf"},

		// Not a reserved name
		{"CONNECT.txt", "CONNECT.txt"},
		{"console.log", "console.log"},
	}
	for _, tc := range cases {
		got := sanitizeFilename(tc.input)
		if got != tc.expected {
			t.Errorf("sanitize(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}
