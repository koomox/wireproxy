package wire

import (
	"fmt"
	"path/filepath"
	"strings"
)

func Trim(s string) string {
	var ch []byte
	for i := range s {
		switch s[i] {
		case '`', '"', ' ':
		case '#':
			break
		default:
			ch = append(ch, s[i])
		}
	}
	return string(ch)
}

func TrimSpace(s string) string {
	var ch []byte
	for i := range s {
		switch s[i] {
		case '`', '"', ' ', '[', ']':
		default:
			ch = append(ch, s[i])
		}
	}
	return string(ch)
}

func Split(s, sep string) (elements []string) {
	r := strings.Split(s, sep)
	for i := range r {
		v := Trim(r[i])
		if v == "" {
			continue
		}
		elements = append(elements, v)
	}
	return
}

func ParsePair(s string) (key, value string) {
	n := len(s)
	for i := 0; i < n; i++ {
		switch s[i] {
		case '=':
			if (i - 1) == 0 {
				return "", s[i:]
			}
			if (i + 1) == n {
				return s[:i-1], ""
			}
			return s[:i], s[i+1:]
		}
	}
	return "", ""
}

func FromArgs(args ...interface{}) (values map[string]string) {
	values = make(map[string]string)
	for i := range args {
		k, v := ParsePair(fmt.Sprintf("%v", args[i]))
		values[k] = v
	}
	return
}

func GetPath(pa string) string {
	f, err := filepath.Abs(filepath.Dir(pa))
	if err != nil {
		return f
	}
	return strings.Replace(f, "\\", "/", -1)
}

func GetValue(args map[string]string, keys ...string) (value string, ok bool) {
	for idx := range args {
		for i := range keys {
			if keys[i] == idx {
				return args[idx], true
			}
		}
	}
	return
}
