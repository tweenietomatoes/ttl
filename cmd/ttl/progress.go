package main

import (
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/term"
)

// progress draws the transfer bar on stderr. Uploads add bytes as the
// encryptor hands them to the transport and move the counter back when a
// part is sent again; downloads add bytes as they arrive.
type progress struct {
	n       int64
	total   int64
	display int64
	last    time.Time
	quiet   bool // --json: nothing at all on stderr
	tty     bool // bar only on a terminal
	done    bool
	frame   int
	speed   float64   // EMA-smoothed bytes/sec
	prevN   int64     // bytes at previous render
	prevT   time.Time // time of previous render
}

// newProgress returns a bar for a transfer of total bytes on the wire.
// displaySize is the file size shown to the user (0 = total).
// quiet suppresses all output (used by --json mode).
func newProgress(total, displaySize int64, quiet bool) *progress {
	if displaySize <= 0 {
		displaySize = total
	}
	return &progress{
		total:   total,
		display: displaySize,
		quiet:   quiet,
		tty:     !quiet && term.IsTerminal(int(os.Stderr.Fd())), //nolint:gosec // stderr fd is 0..2, fits int
	}
}

// add records n more bytes and redraws at most every 150 ms.
func (p *progress) add(n int) {
	p.n += int64(n)
	if !p.tty || p.done {
		return
	}
	now := time.Now()
	if p.prevT.IsZero() {
		p.prevT = now
	}
	if now.Sub(p.last) >= 150*time.Millisecond {
		if dt := now.Sub(p.prevT).Seconds(); dt > 0 {
			instant := float64(p.n-p.prevN) / dt
			if p.speed == 0 {
				p.speed = instant
			} else {
				p.speed = 0.3*instant + 0.7*p.speed
			}
			p.prevN = p.n
			p.prevT = now
		}
		p.last = now
		p.render()
	}
}

// set moves the counter to n: a part sent again starts over from its
// offset, and the speed estimate restarts from there.
func (p *progress) set(n int64) {
	p.n = n
	p.prevN = n
	p.prevT = time.Time{}
}

// finish draws the final state and ends the line. Safe to call twice.
func (p *progress) finish() {
	if p.done {
		return
	}
	p.done = true
	if !p.tty {
		return
	}
	p.render()
	fmt.Fprintln(os.Stderr)
}

// note prints msg on its own line (a lost connection, a retry) and redraws
// the bar under it. Silent in --json mode.
func (p *progress) note(msg string) {
	if p.quiet {
		return
	}
	if !p.tty {
		fmt.Fprintln(os.Stderr, msg)
		return
	}
	fmt.Fprintf(os.Stderr, "\r\033[K%s%s%s\n", c(cAmber), msg, c(cReset))
	if !p.done {
		p.render()
	}
}

// reader counts what passes through r into the bar.
func (p *progress) reader(r io.Reader) io.Reader {
	return &progressReader{r: r, p: p}
}

type progressReader struct {
	r io.Reader
	p *progress
}

func (pr *progressReader) Read(buf []byte) (int, error) {
	n, err := pr.r.Read(buf)
	pr.p.add(n)
	return n, err
}

// barWidth adapts the bar to the terminal width (min 10, max 60, fallback 20).
func barWidth() int {
	w, _, err := term.GetSize(int(os.Stderr.Fd())) //nolint:gosec // stderr fd is 0..2, fits int
	if err != nil || w < 40 {
		return 20
	}
	// Fixed parts: "1.2 MB / 4.2 MB" (≤17) + gaps (4) + "100%" (4) + suffix (≤22) ≈ 47
	bw := w - 47
	if bw < 10 {
		bw = 10
	}
	if bw > 60 {
		bw = 60
	}
	return bw
}

func (p *progress) render() {
	p.frame++

	// Two flowing layers, nothing static:
	//   bg    : twinkling stardust, slow drift  (period 5, half speed)
	//   planet: rare planet flyby                (period 19, full speed)
	bg := []rune{'·', '·', '·', '✧', ' '}
	planet := []rune{
		' ', ' ', ' ', ' ', ' ', ' ', ' ',
		'✧', '★', '◉', '★', '✧',
		' ', ' ', ' ', ' ', ' ', ' ', ' ',
	}

	brighter := func(a, b rune) rune {
		rank := [4]rune{'·', '✧', '★', '◉'}
		for i := len(rank) - 1; i >= 0; i-- {
			if a == rank[i] || b == rank[i] {
				return rank[i]
			}
		}
		if a != ' ' {
			return a
		}
		return b
	}

	compose := func(i int) rune {
		b := bg[((i-p.frame/2)%len(bg)+len(bg))%len(bg)]
		pl := planet[((i-p.frame)%len(planet)+len(planet))%len(planet)]
		return brighter(b, pl)
	}

	// Scale current bytes to display size for the label
	shown := p.n
	if p.display != p.total && p.total > 0 {
		shown = p.n * p.display / p.total
	}

	// Scale speed to display units so the user sees file speed, not encrypted speed
	displaySpeed := p.speed
	if p.display != p.total && p.total > 0 {
		displaySpeed = p.speed * float64(p.display) / float64(p.total)
	}

	suffix := ""
	if displaySpeed >= 1 {
		suffix += "  " + humanBytes(int64(displaySpeed)) + "/s"
	}

	if p.total <= 0 {
		spin := make([]rune, 9)
		for i := range spin {
			spin[i] = compose(i)
		}
		fmt.Fprintf(os.Stderr, "\r%s%s%s / ∞  %s%s%s%s%s\033[K",
			c(cWhite), humanBytes(shown), c(cReset),
			c(cTeal), string(spin), c(cReset),
			c(cGray), suffix+c(cReset))
		return
	}

	pct := int(float64(p.n) / float64(p.total) * 100)
	if pct > 100 {
		pct = 100
	}
	w := barWidth()
	filled := pct * w / 100

	filledBar := make([]rune, filled)
	for i := 0; i < filled; i++ {
		filledBar[i] = compose(i)
	}
	emptyBar := make([]rune, w-filled)
	for i := range emptyBar {
		emptyBar[i] = '·'
	}

	if displaySpeed >= 1 && p.n < p.total {
		remaining := float64(p.total-p.n) / p.speed
		sec := int(remaining)
		if sec < 60 {
			suffix += fmt.Sprintf("  ~%ds", sec)
		} else {
			suffix += fmt.Sprintf("  ~%d:%02d", sec/60, sec%60)
		}
	}

	fmt.Fprintf(os.Stderr, "\r%s%s%s / %s  %s%s%s%s%s  %s%d%%%s%s\033[K",
		c(cWhite), humanBytes(shown), c(cReset),
		humanBytes(p.display),
		c(cTeal), string(filledBar), c(cReset),
		c(cGray), string(emptyBar),
		c(cReset, cBold), pct, c(cReset),
		c(cGray)+suffix+c(cReset))
}
