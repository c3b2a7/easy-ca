package internal

import "strings"

type Tokenizer struct {
	value     string
	separator uint8
	index     int
	buf       strings.Builder
}

func NewTokenizer(value string, sep uint8) Tokenizer {
	return Tokenizer{
		value:     value,
		separator: sep,
		index:     -1,
	}
}

func (t *Tokenizer) HasMoreTokens() bool {
	return len(t.value) != t.index
}

func (t *Tokenizer) NextToken() string {
	if len(t.value) == t.index {
		return ""
	}

	end := t.index + 1
	quoted, escaped := false, false
	buf := t.buf
	buf.Reset()

	for end != len(t.value) {
		c := t.value[end]
		if c == '"' {
			if !escaped {
				quoted = !quoted
			}
			buf.WriteByte(c)
			escaped = false
		} else {
			if escaped || quoted {
				buf.WriteByte(c)
				escaped = false
			} else if c == '\\' {
				buf.WriteByte(c)
				escaped = true
			} else if c == t.separator {
				break
			} else {
				buf.WriteByte(c)
			}
		}
		end++
	}

	t.index = end
	return buf.String()
}
