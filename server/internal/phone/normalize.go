package phone

import (
	"fmt"
	"regexp"
	"strings"
)

var stripChars = regexp.MustCompile(`[\s\-\(\)\.]`)

// Normalize converts a phone input to E.164-like format.
// Returns the normalized string or an error for invalid input.
// Rules: trim, remove spaces/parentheses/hyphens/dots, 00→+, must start with +, digits only after.
func Normalize(input string) (string, error) {
	s := strings.TrimSpace(input)
	if s == "" {
		return "", fmt.Errorf("phone number is empty")
	}
	s = stripChars.ReplaceAllString(s, "")
	if s == "" {
		return "", fmt.Errorf("phone number has no digits")
	}
	if strings.HasPrefix(s, "00") {
		s = "+" + s[2:]
	}
	if !strings.HasPrefix(s, "+") {
		return "", fmt.Errorf("phone must start with + or 00")
	}
	digits := strings.TrimPrefix(s, "+")
	if len(digits) < 6 {
		return "", fmt.Errorf("phone number too short")
	}
	for _, r := range digits {
		if r < '0' || r > '9' {
			return "", fmt.Errorf("phone contains invalid characters")
		}
	}
	return s, nil
}

// NormalizeOrEmpty returns normalized phone or empty string if invalid (for batch/sync).
func NormalizeOrEmpty(input string) string {
	s, err := Normalize(input)
	if err != nil {
		return ""
	}
	return s
}
