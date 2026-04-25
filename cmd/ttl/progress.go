package main

import (
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/term"
)

type progressReader struct {
	r       io.Reader
	n       int64
	total   int64
	display int64
	last    time.Time
	tty     bool
	done    bool
	frame   int
	speed   float64   // EMA-smoothed bytes/sec
	prevN   int64     // bytes at previous render
	prevT   time.Time // time of previous render
}

// newProgressReader wraps r with a progress bar.
// total is the real byte count used for percentage calculation.
// displaySize is the file size shown to the user (pass 0 to use total).
// quiet suppresses all output (used by --json mode).
func newProgressReader(r io.Reader, total, displaySize int64, quiet bool) *progressReader {
	if displaySize <= 0 {
		displaySize = total
	}
	return &progressReader{
		r:       r,
		total:   total,
		display: displaySize,
		tty:     !quiet && term.IsTerminal(int(os.Stderr.Fd())),
	}
}

func (p *progressReader) Read(buf []byte) (int, error) {
	n, err := p.r.Read(buf)
	p.n += int64(n)
	if !p.tty || p.done {
		return n, err
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
	if err != nil {
		p.render()
		fmt.Fprintln(os.Stderr)
		p.done = true
	}
	return n, err
}

// barWidth adapts the bar to the terminal width (min 10, max 60, fallback 20).
func barWidth() int {
	w, _, err := term.GetSize(int(os.Stderr.Fd()))
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

func (p *progressReader) render() {
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
