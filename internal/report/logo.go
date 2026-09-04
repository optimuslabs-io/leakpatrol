// Copyright 2026 Optimus Labs (Civilizations research team)
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"fmt"
	"io"
	"math/rand"
	"strings"
	"time"

	"github.com/optimuslabs-io/leakpatrol/internal/buildinfo"
)

// The animated LEAKPATROL logo, in the Optimus Labs house style shared with
// grokpatrol and perceptron: a "glitch-decode reveal" -- the wordmark starts as
// random mechanical glyphs, a bright aqua scan beam sweeps left-to-right, and the
// columns behind it settle into the real letters in a teal->aqua gradient. It
// writes to the caller's io.Writer (the Progress STDERR stream), never stdout, so
// `leakpatrol --json | jq` stays byte-for-byte clean. The caller gates it on
// stderr being a TTY with colour, so a pipe or a log file never sees an escape code.
//
// Hand-embedded so nothing new links into the binary. Regenerate with:
//
//	figlet -f standard LEAKPATROL
//
// No marker string may appear in this art or its taglines -- the binary is scanned
// for its own indicators in tests.
const logoArt = `
 _     _____    _    _  __ ____    _  _____ ____   ___  _
| |   | ____|  / \  | |/ /|  _ \  / \|_   _|  _ \ / _ \| |
| |   |  _|   / _ \ | ' / | |_) |/ _ \ | | | |_) | | | | |
| |___| |___ / ___ \| . \ |  __// ___ \| | |  _ <| |_| | |___
|_____|_____/_/   \_\_|\_\|_|  /_/   \_\_| |_| \_\\___/|_____|`

// logoSubtitle is the three lines beneath the wordmark: the question this scan
// answers, the trust contract, then provenance.
func logoSubtitle() []string {
	return []string{
		"     Coder registry-hijack exposure check · " + buildinfo.Advisory,
		"     Read-only · offline except your own Coder server · never contacts the exfil endpoint",
		"     " + buildinfo.Repo + " · " + buildinfo.Attribution,
	}
}

// Brand 256-colour ramp (deep teal -> bright aqua), one shade per wordmark row,
// and the bright-aqua scan beam.
var logoRamp = []int{23, 30, 36, 37, 43, 44}

const logoBeam = "\033[38;5;51m\033[1m"

var logoGlitch = []rune("#@▒▓█░╳═║╬┼┴┬┤├┯┷┝┥◊◆▰▱◢◣◤◥")

// animateLogo plays the reveal to w. With colour off it falls back to the plain,
// ANSI-free logo so nothing can leak escapes.
func animateLogo(w io.Writer, s Style) {
	if !s.Color {
		plainLogo(w, s)
		return
	}
	art := strings.Split(strings.Trim(logoArt, "\n"), "\n")
	rows := len(art)
	cols := 0
	for _, line := range art {
		if n := len([]rune(line)); n > cols {
			cols = n
		}
	}
	padded := make([][]rune, rows)
	for i, line := range art {
		r := []rune(line)
		for len(r) < cols {
			r = append(r, ' ')
		}
		padded[i] = r
	}
	settled := make([]string, rows)
	for i := range settled {
		settled[i] = fmt.Sprintf("\033[38;5;%dm\033[1m", logoRamp[min(i, len(logoRamp)-1)])
	}

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	glitch := func() rune { return logoGlitch[rng.Intn(len(logoGlitch))] }

	for r := 0; r < rows; r++ {
		var b strings.Builder
		b.WriteString("\033[2m")
		for c := 0; c < cols; c++ {
			b.WriteRune(glitch())
		}
		b.WriteString(reset)
		fmt.Fprintln(w, b.String())
	}
	time.Sleep(60 * time.Millisecond)

	step := cols / 60
	if step < 1 {
		step = 1
	}
	for col := 0; col <= cols; col += step {
		fmt.Fprintf(w, "\033[%dF", rows)
		for r := 0; r < rows; r++ {
			var b strings.Builder
			b.WriteString("\033[2K")
			for c := 0; c < cols; c++ {
				ch := padded[r][c]
				switch {
				case c < col:
					b.WriteString(settled[r])
					b.WriteRune(ch)
				case c < col+step:
					b.WriteString(logoBeam)
					if ch == ' ' {
						b.WriteRune(glitch())
					} else {
						b.WriteRune(ch)
					}
				default:
					b.WriteString("\033[2m")
					b.WriteRune(glitch())
				}
			}
			b.WriteString(reset)
			fmt.Fprintln(w, b.String())
		}
		time.Sleep(18 * time.Millisecond)
	}

	fmt.Fprintf(w, "\033[%dF", rows)
	for r := 0; r < rows; r++ {
		fmt.Fprintf(w, "\033[2K%s%s%s\n", settled[r], string(padded[r]), reset)
	}
	for i, line := range logoSubtitle() {
		if i == 2 {
			fmt.Fprintln(w, s.c(dim, line))
		} else {
			fmt.Fprintln(w, s.c(cyan+bold, line))
		}
		time.Sleep(15 * time.Millisecond)
	}
	fmt.Fprintln(w)
	time.Sleep(300 * time.Millisecond)
}

// plainLogo prints the wordmark and subtitle with no ANSI at all.
func plainLogo(w io.Writer, _ Style) {
	fmt.Fprintln(w, strings.Trim(logoArt, "\n"))
	for _, line := range logoSubtitle() {
		fmt.Fprintln(w, line)
	}
	fmt.Fprintln(w)
}
