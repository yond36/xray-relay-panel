// Package coreversion defines explicit official Xray tags and their release catalogue.
package coreversion

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
)

var tagPattern = regexp.MustCompile(`^v[0-9]{1,4}\.[0-9]{1,3}\.[0-9]{1,3}(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?(?:\+[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$`)

func Normalize(value string) (string, error) {
	if strings.ContainsAny(value, "\x00\r\n\t") {
		return "", errors.New("核心版本不能包含控制字符")
	}
	value = strings.TrimSpace(value)
	if value != "" && !strings.HasPrefix(value, "v") && !strings.HasPrefix(value, "V") {
		value = "v" + value
	}
	if strings.HasPrefix(value, "V") {
		value = "v" + value[1:]
	}
	if len(value) > 80 || !tagPattern.MatchString(value) {
		return "", errors.New("核心版本须为明确的官方 tag，例如 v26.10.31、1.8.24 或 v26.10.31-rc.1")
	}
	return value, nil
}
func Validate(value string) error { _, err := Normalize(value); return err }

// MatchesBinary is used only after official-tag asset provenance and SHA256 were checked.
// Some official prerelease assets report their base version without the tag suffix.
func MatchesBinary(requested, reported string) bool {
	a, err := Normalize(requested)
	if err != nil {
		return false
	}
	b, err := Normalize(reported)
	if err != nil {
		return false
	}
	if a == b {
		return true
	}
	if suffix := strings.IndexAny(a, "-+"); suffix > 0 {
		return a[:suffix] == b
	}
	return false
}

// LegacyAliases identifies pre-calendar cores that predate RAW and REALITY target aliases.
func LegacyAliases(value string) bool {
	v, err := Normalize(value)
	if err != nil {
		return false
	}
	major, _ := strconv.Atoi(strings.Split(strings.TrimPrefix(v, "v"), ".")[0])
	return major < 24
}
