package sealedsecrets

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
	"unicode"
)

// generateFromPattern produces a random string matching a simplified regex-like
// pattern. Supported syntax covers the most common secret-generation use cases:
//
//   - Literal characters: abc
//   - Character classes:  [a-zA-Z0-9], [a-f], [!@#$%]
//   - Shorthand classes:  \d (digit), \w (word), \l (lowercase), \u (uppercase)
//   - Repetition:         {n} exact, {n,m} range (inclusive)
//   - Dot:                . (any printable ASCII, 33-126)
//
// Examples:
//
//	"[a-zA-Z0-9]{32}"         → 32-char alphanumeric
//	"[a-f0-9]{64}"            → 64-char hex
//	"[A-Za-z0-9!@#$%]{16}"   → 16-char password with specials
//	"sk_live_\w{24}"          → prefixed API key
func generateFromPattern(pattern string) (string, error) {
	var result strings.Builder
	runes := []rune(pattern)
	i := 0

	for i < len(runes) {
		ch := runes[i]

		switch {
		case ch == '[':
			// Parse character class
			end := indexRune(runes, i+1, ']')
			if end == -1 {
				return "", fmt.Errorf("unclosed character class at position %d", i)
			}
			chars, err := expandCharClass(runes[i+1 : end])
			if err != nil {
				return "", fmt.Errorf("invalid character class at position %d: %w", i, err)
			}
			i = end + 1

			count, advance, err := parseRepetition(runes, i)
			if err != nil {
				return "", err
			}
			i += advance

			for range count {
				c, err := pickRandom(chars)
				if err != nil {
					return "", err
				}
				result.WriteRune(c)
			}

		case ch == '\\' && i+1 < len(runes):
			chars := expandShorthand(runes[i+1])
			if chars == nil {
				// Escaped literal
				result.WriteRune(runes[i+1])
				i += 2
				continue
			}
			i += 2

			count, advance, err := parseRepetition(runes, i)
			if err != nil {
				return "", err
			}
			i += advance

			for range count {
				c, err := pickRandom(chars)
				if err != nil {
					return "", err
				}
				result.WriteRune(c)
			}

		case ch == '.':
			i++
			count, advance, err := parseRepetition(runes, i)
			if err != nil {
				return "", err
			}
			i += advance

			printable := make([]rune, 0, 94)
			for c := rune(33); c <= 126; c++ {
				printable = append(printable, c)
			}
			for range count {
				c, err := pickRandom(printable)
				if err != nil {
					return "", err
				}
				result.WriteRune(c)
			}

		default:
			// Literal character
			result.WriteRune(ch)
			i++
		}
	}

	return result.String(), nil
}

// expandCharClass expands a character class body (contents between [ and ]) into
// a slice of runes. Supports ranges like a-z and individual characters.
func expandCharClass(body []rune) ([]rune, error) {
	var chars []rune
	i := 0
	for i < len(body) {
		if body[i] == '\\' && i+1 < len(body) {
			sh := expandShorthand(body[i+1])
			if sh != nil {
				chars = append(chars, sh...)
				i += 2
				continue
			}
			chars = append(chars, body[i+1])
			i += 2
			continue
		}

		if i+2 < len(body) && body[i+1] == '-' {
			lo := body[i]
			hi := body[i+2]
			if hi < lo {
				return nil, fmt.Errorf("invalid range %c-%c", lo, hi)
			}
			for c := lo; c <= hi; c++ {
				chars = append(chars, c)
			}
			i += 3
		} else {
			chars = append(chars, body[i])
			i++
		}
	}
	return chars, nil
}

// expandShorthand returns the character set for a shorthand class, or nil if
// the rune is not a recognized shorthand.
func expandShorthand(ch rune) []rune {
	switch ch {
	case 'd':
		return rangeRunes('0', '9')
	case 'w':
		return append(append(append(rangeRunes('a', 'z'), rangeRunes('A', 'Z')...), rangeRunes('0', '9')...), '_')
	case 'l':
		return rangeRunes('a', 'z')
	case 'u':
		return rangeRunes('A', 'Z')
	default:
		return nil
	}
}

// parseRepetition reads an optional {n} or {n,m} repetition suffix starting at
// position i. Returns the count to repeat, the number of runes consumed, and
// any error. If no repetition is found, returns (1, 0, nil).
func parseRepetition(runes []rune, i int) (int, int, error) {
	if i >= len(runes) || runes[i] != '{' {
		return 1, 0, nil
	}
	end := indexRune(runes, i+1, '}')
	if end == -1 {
		return 0, 0, fmt.Errorf("unclosed repetition at position %d", i)
	}
	body := string(runes[i+1 : end])
	advance := end - i + 1

	if idx := strings.Index(body, ","); idx != -1 {
		minStr := strings.TrimSpace(body[:idx])
		maxStr := strings.TrimSpace(body[idx+1:])
		min, err := parsePositiveInt(minStr)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid repetition min %q: %w", minStr, err)
		}
		max, err := parsePositiveInt(maxStr)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid repetition max %q: %w", maxStr, err)
		}
		if max < min {
			return 0, 0, fmt.Errorf("repetition max %d < min %d", max, min)
		}
		n, err := cryptoRandIntn(max - min + 1)
		if err != nil {
			return 0, 0, err
		}
		return min + n, advance, nil
	}

	n, err := parsePositiveInt(strings.TrimSpace(body))
	if err != nil {
		return 0, 0, fmt.Errorf("invalid repetition count %q: %w", body, err)
	}
	return n, advance, nil
}

func rangeRunes(lo, hi rune) []rune {
	out := make([]rune, 0, hi-lo+1)
	for c := lo; c <= hi; c++ {
		out = append(out, c)
	}
	return out
}

func indexRune(runes []rune, start int, target rune) int {
	for i := start; i < len(runes); i++ {
		if runes[i] == target {
			return i
		}
	}
	return -1
}

func pickRandom(chars []rune) (rune, error) {
	if len(chars) == 0 {
		return 0, fmt.Errorf("empty character set")
	}
	idx, err := cryptoRandIntn(len(chars))
	if err != nil {
		return 0, err
	}
	return chars[idx], nil
}

func cryptoRandIntn(n int) (int, error) {
	max := big.NewInt(int64(n))
	val, err := rand.Int(rand.Reader, max)
	if err != nil {
		return 0, fmt.Errorf("crypto/rand failed: %w", err)
	}
	return int(val.Int64()), nil
}

func parsePositiveInt(s string) (int, error) {
	if s == "" {
		return 0, fmt.Errorf("empty number")
	}
	n := 0
	for _, ch := range s {
		if !unicode.IsDigit(ch) {
			return 0, fmt.Errorf("non-digit character %q", ch)
		}
		n = n*10 + int(ch-'0')
	}
	if n > 1024 {
		return 0, fmt.Errorf("repetition count %d exceeds maximum 1024", n)
	}
	return n, nil
}
