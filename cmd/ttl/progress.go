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
func newProgressReader(r io.Reader, total, displaySize int64) *progressReader {
	if displaySize <= 0 {
		displaySize = total
	}
	return &progressReader{
		r:       r,
		total:   total,
		display: displaySize,
		tty:     term.IsTerminal(int(os.Stderr.Fd())),
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

func (p *progressReader) render() {
	p.frame++

	// Two flowing layers, nothing static:
	//   bg     — twinkling stardust, slow drift  (period 5, half speed)
	//   planet — rare planet flyby                (period 19, full speed)
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
		fmt.Fprintf(os.Stderr, "\r%s / ∞  %s%s\033[K", humanBytes(shown), string(spin), suffix)
		return
	}

	pct := int(float64(p.n) / float64(p.total) * 100)
	if pct > 100 {
		pct = 100
	}
	const w = 30
	filled := pct * w / 100

	bar := make([]rune, w)
	for i := 0; i < w; i++ {
		if i < filled {
			bar[i] = compose(i)
		} else {
			bar[i] = '·'
		}
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

	fmt.Fprintf(os.Stderr, "\r%s / %s  %s  %d%%%s\033[K",
		humanBytes(shown), humanBytes(p.display), string(bar), pct, suffix)
}
