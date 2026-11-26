// Package jsonpath reads path text, which the rules allow here alone.
package jsonpath

import "strings"

func rootBracket(p string) bool {
	return strings.HasPrefix(p, "$['")
}
