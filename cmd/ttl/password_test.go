package main

import "testing"

func TestGeneratePassword_Length(t *testing.T) {
	p, err := generatePassword(8)
	if err != nil {
		t.Fatal(err)
	}
	if len(p) != 8 {
		t.Fatalf("expected length 8, got %d", len(p))
	}
}

func TestGeneratePassword_Charset(t *testing.T) {
	p, err := generatePassword(100)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range p {
		found := false
		for _, ch := range passwordChars {
			if c == ch {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("char %c not in charset", c)
		}
	}
}