package cmd

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestReadWordlist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pwds.txt")
	content := "\ufefffirstpass1\r\n# comment\r\n\"quotedpass1\"\r\nsecondpass1,label\r\n\r\ntiny\r\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readWordlist(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"firstpass1", "quotedpass1", "secondpass1"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("readWordlist = %v, want %v", got, want)
	}
}

func TestReadWordlistEmptyPathIsNoop(t *testing.T) {
	words, err := readWordlist("")
	if err != nil || words != nil {
		t.Errorf("readWordlist(\"\") = %v, %v", words, err)
	}
}

func TestReadWordlistRejectsOversizedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "huge.txt")
	data := strings.Repeat("a\n", 700000)
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readWordlist(path); err == nil {
		t.Error("oversized wordlist was accepted")
	}
}
