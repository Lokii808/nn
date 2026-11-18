package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"
	"unicode"
)

var (
	reJSVars      = regexp.MustCompile(`(?:var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)`)
	reURLParams   = regexp.MustCompile(`[?&]([a-zA-Z0-9_\-]+)=([^&\s"'<>\x00-\x1f]*)`)
	reHTMLIDs     = regexp.MustCompile(`(?i)id\s*=\s*["']([^"']+)["']`)
	reHTMLNames   = regexp.MustCompile(`(?i)name\s*=\s*["']([^"']+)["']`)
	// NOVAS REGEX ADICIONADAS:
	reHTMLEvents  = regexp.MustCompile(`(?i)\bon[a-z]+\s*=\s*["']([^"']+)["']`) // onclick, onerror, etc
	reHTMLActions = regexp.MustCompile(`(?i)(?:action|src|href)\s*=\s*["']([^"']+)["']`)
	reEndpoints   = regexp.MustCompile(`(?i)["'](\/[a-zA-Z0-9_\-\/]+(?:\.[a-z0-9]+)?)["']`) // Endpoints como /api/v1/user
	reInputTypes  = regexp.MustCompile(`(?i)type\s*=\s*["']([^"']+)["']`)
)

func main() {
	var minlength int
	flag.IntVar(&minlength, "min", 1, "min length of string to be output")
	var maxlength int
	flag.IntVar(&maxlength, "max", 40, "max length aumentada para endpoints")
	var alphaNumOnly bool
	flag.BoolVar(&alphaNumOnly, "alpha-num-only", false, "return only strings containing at least one letter and one number")
	var delimExceptions string
	flag.StringVar(&delimExceptions, "delim-exceptions", "", "don't use the characters provided as delimiters")

	var noTokens bool
	flag.BoolVar(&noTokens, "no-tokens", false, "skip generic tokenizer output")
	
	flag.Parse()

	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error reading stdin:", err)
		os.Exit(1)
	}
	content := string(input)

	seen := make(map[string]bool)
	emit := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			return
		}
		if len(s) < minlength || len(s) > maxlength {
			return
		}
		seen[s] = true
		fmt.Println(s)
	}

	// Execução das extrações
	extract := func(re *regexp.Regexp, text string) {
		for _, m := range re.FindAllStringSubmatch(text, -1) {
			if len(m) > 1 {
				emit(m[1])
			}
		}
	}

	extract(reJSVars, content)
	extract(reHTMLIDs, content)
	extract(reHTMLNames, content)
	extract(reHTMLEvents, content)
	extract(reHTMLActions, content)
	extract(reEndpoints, content)
	extract(reInputTypes, content)

	// Lógica especial para URL Params (extrai a chave e tenta decodificar o valor)
	for _, m := range reURLParams.FindAllStringSubmatch(content, -1) {
		if len(m) > 1 {
			emit(m[1])
		}
		if len(m) > 2 && m[2] != "" {
			if dec, err := url.QueryUnescape(m[2]); err == nil {
				emit(dec)
			} else {
				emit(m[2])
			}
		}
	}

	if !noTokens {
		r := bufio.NewReader(strings.NewReader(content))
		var out strings.Builder
		maybeURLEncoded, includesLetters, includesNumbers := false, false, false

		reset := func() {
			maybeURLEncoded, includesLetters, includesNumbers = false, false, false
			out.Reset()
		}

		for {
			ch, _, err := r.ReadRune()
			if err != nil {
				break
			}

			l := unicode.In(ch, unicode.L)
			if l { includesLetters = true }
			n := unicode.In(ch, unicode.N)
			if n { includesNumbers = true }

			if !l && !n && !isDelimException(ch, delimExceptions) {
				if out.Len() >= minlength && out.Len() <= maxlength {
					if !alphaNumOnly || (includesLetters && includesNumbers) {
						str := out.String()
						if maybeURLEncoded {
							if dec, err := url.QueryUnescape(str); err == nil { str = dec }
						}
						emit(str)
					}
				}
				reset()
				continue
			}
			if ch == '%' { maybeURLEncoded = true }
			out.WriteRune(ch)
		}
	}
}

func isDelimException(r rune, delims string) bool {
	for _, comp := range delims {
		if r == comp { return true }
	}
	return false
}