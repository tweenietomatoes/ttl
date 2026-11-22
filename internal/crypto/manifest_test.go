package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// manifest-vectors.json is a copy of the server repository's golden vectors
// (internal/accountcrypto/testdata): the CLI makes and opens a manifest
// byte for byte as the server's reference and the browser's workers do.
type manifestVectorFile struct {
	Label string `json:"label"`
	Magic string `json:"magic"`
	Keys  []struct {
		FileKey     string `json:"file_key"`
		ManifestKey string `json:"manifest_key"`
	} `json:"keys"`
	Seals []struct {
		Name    string `json:"name"`
		FileKey string `json:"file_key"`
		Token   string `json:"token"`
		Nonce   string `json:"nonce"`
		Records []struct {
			Type  byte   `json:"type"`
			Value string `json:"value"`
			// Files: a SHA-256 list of this many files, the i-th (from 0)
			// being SHA-256 of i as a big-endian uint32.
			Files int `json:"files"`
		} `json:"records"`
		Sealed       string `json:"sealed"`
		SealedSHA256 string `json:"sealed_sha256"`
		SealedLen    int    `json:"sealed_len"`
	} `json:"seals"`
	Opens []struct {
		Name    string `json:"name"`
		FileKey string `json:"file_key"`
		Token   string `json:"token"`
		Sealed  string `json:"sealed"`
		// Zeros: Sealed is this many zero bytes as they are, sealed with
		// Nonce.
		Zeros  int      `json:"zeros"`
		Nonce  string   `json:"nonce"`
		OK     bool     `json:"ok"`
		SHA256 []string `json:"sha256"`
	} `json:"opens"`
}

func TestManifestVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/manifest-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v manifestVectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	un := func(s string) []byte {
		t.Helper()
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	hx := hex.EncodeToString
	if v.Label != manifestLabel || string(un(v.Magic)) != ManifestMagic || len(v.Keys) == 0 || len(v.Seals) == 0 || len(v.Opens) == 0 {
		t.Fatalf("label %q, magic %q, %d keys, %d seals, %d opens", v.Label, un(v.Magic), len(v.Keys), len(v.Seals), len(v.Opens))
	}
	for _, k := range v.Keys {
		if mk, err := manifestKey(un(k.FileKey)); err != nil || hx(mk) != k.ManifestKey {
			t.Errorf("manifest key of %s: %x %v", k.FileKey, mk, err)
		}
	}
	for _, s := range v.Seals {
		var recs []ManifestRecord
		var want []string
		for _, r := range s.Records {
			rec := ManifestRecord{Type: r.Type, Value: un(r.Value)}
			if r.Files > 0 {
				rec.Value = nil
				for i := range r.Files {
					d := sha256.Sum256(binary.BigEndian.AppendUint32(nil, uint32(i))) //nolint:gosec // i < Files
					rec.Value = append(rec.Value, d[:]...)
				}
			}
			recs = append(recs, rec)
			if rec.Type == ManifestSHA256 {
				for i := 0; i < len(rec.Value); i += 32 {
					want = append(want, hx(rec.Value[i:i+32]))
				}
			}
		}
		sealed, err := SealManifest(un(s.FileKey), s.Token, un(s.Nonce), recs...)
		if err != nil {
			t.Fatalf("%s: %v", s.Name, err)
		}
		d := sha256.Sum256(sealed)
		if len(sealed) != s.SealedLen || (s.Sealed != "" && hx(sealed) != s.Sealed) || (s.SealedSHA256 != "" && hx(d[:]) != s.SealedSHA256) {
			t.Errorf("%s: sealed differently", s.Name)
		}
		m, err := OpenManifest(un(s.FileKey), s.Token, sealed)
		if err != nil || len(m.SHA256) != len(want) {
			t.Fatalf("%s: opened %d digests, %v", s.Name, len(m.SHA256), err)
		}
		for i := range want {
			if hx(m.SHA256[i]) != want[i] {
				t.Errorf("%s: digest %d", s.Name, i)
			}
		}
	}
	for _, o := range v.Opens {
		sealed := un(o.Sealed)
		if o.Zeros > 0 {
			if sealed, err = sealManifestPadded(un(o.FileKey), o.Token, un(o.Nonce), make([]byte, o.Zeros)); err != nil {
				t.Fatal(err)
			}
		}
		m, err := OpenManifest(un(o.FileKey), o.Token, sealed)
		if !o.OK {
			if err == nil {
				t.Errorf("%s: opened, want refused", o.Name)
			}
			continue
		}
		if err != nil || len(m.SHA256) != len(o.SHA256) {
			t.Errorf("%s: %d digests, %v", o.Name, len(m.SHA256), err)
			continue
		}
		for i := range o.SHA256 {
			if hx(m.SHA256[i]) != o.SHA256[i] {
				t.Errorf("%s: digest %d", o.Name, i)
			}
		}
	}
}

// A manifest opens only with its own file key and token, and not once a
// byte of it changed.
func TestManifestBound(t *testing.T) {
	key := bytes.Repeat([]byte{7}, KeySize)
	nonce := bytes.Repeat([]byte{9}, 24)
	sum := sha256.Sum256([]byte("hello"))
	sealed, err := SealManifest(key, "aBcDeFgHiJ", nonce, ManifestRecord{Type: ManifestSHA256, Value: sum[:]})
	if err != nil || len(sealed) != ManifestMin {
		t.Fatalf("sealed %d bytes, %v", len(sealed), err)
	}
	if m, err := OpenManifest(key, "aBcDeFgHiJ", sealed); err != nil || len(m.SHA256) != 1 || !bytes.Equal(m.SHA256[0], sum[:]) {
		t.Fatalf("own: %v %v", m, err)
	}
	other := bytes.Repeat([]byte{8}, KeySize)
	if _, err := OpenManifest(other, "aBcDeFgHiJ", sealed); err == nil {
		t.Error("opened with another file key")
	}
	if _, err := OpenManifest(key, "aBcDeFgHiK", sealed); err == nil {
		t.Error("opened with another token")
	}
	for _, at := range []int{0, 8, 40, len(sealed) - 1} {
		bad := bytes.Clone(sealed)
		bad[at] ^= 1
		if _, err := OpenManifest(key, "aBcDeFgHiJ", bad); err == nil {
			t.Errorf("opened with byte %d changed", at)
		}
	}
	if _, err := OpenManifest(key, "aBcDeFgHiJ", sealed[:len(sealed)-1]); err == nil {
		t.Error("opened cut short")
	}
	if _, err := SealManifest(key[:16], "aBcDeFgHiJ", nonce, ManifestRecord{Type: ManifestSHA256, Value: sum[:]}); err == nil {
		t.Error("sealed with a short key")
	}
}

func TestProbeTail(t *testing.T) {
	h := make([]byte, HeaderSize)
	copy(h, Magic)
	binary.BigEndian.PutUint16(h[MetaLenOffset:], 30)
	probe := append(h, make([]byte, 30)...)
	if tail := ProbeTail(probe); tail != nil {
		t.Errorf("no manifest: %d bytes", len(tail))
	}
	if tail := ProbeTail(append(bytes.Clone(probe), 1, 2, 3)); !bytes.Equal(tail, []byte{1, 2, 3}) {
		t.Errorf("manifest: %v", tail)
	}
	if tail := ProbeTail(h[:10]); tail != nil {
		t.Errorf("short: %v", tail)
	}
}
