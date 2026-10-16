package review

import (
	"fmt"
	"strconv"
	"strings"
)

// parseZon reads a Zig object notation file, such as build.zig.zon, into maps (for .{ .a =
// x }), slices (for .{ x, y }), strings, enum literals (as ".name") and numbers (as their
// text). It reads the subset package manifests use, nothing more.
func parseZon(text string) (any, error) {
	p := &zonParser{s: text}
	v, err := p.value()
	if err != nil {
		return nil, err
	}
	p.space()
	if p.i != len(p.s) {
		return nil, p.errorf("trailing text")
	}
	return v, nil
}

type zonParser struct {
	s string
	i int
}

func (p *zonParser) errorf(format string, args ...any) error {
	line := 1 + strings.Count(p.s[:p.i], "\n")
	return fmt.Errorf("zon line %d: %s", line, fmt.Sprintf(format, args...))
}

func (p *zonParser) space() {
	for p.i < len(p.s) {
		switch {
		case p.s[p.i] == ' ' || p.s[p.i] == '\t' || p.s[p.i] == '\n' || p.s[p.i] == '\r':
			p.i++
		case strings.HasPrefix(p.s[p.i:], "//"):
			for p.i < len(p.s) && p.s[p.i] != '\n' {
				p.i++
			}
		default:
			return
		}
	}
}

func (p *zonParser) value() (any, error) {
	p.space()
	if p.i >= len(p.s) {
		return nil, p.errorf("unexpected end")
	}
	switch c := p.s[p.i]; {
	case strings.HasPrefix(p.s[p.i:], ".{"):
		p.i += 2
		return p.container()
	case c == '.':
		p.i++
		return "." + p.ident(), nil
	case c == '"':
		return p.str()
	default:
		start := p.i
		for p.i < len(p.s) && strings.IndexByte(" \t\r\n,}", p.s[p.i]) < 0 {
			p.i++
		}
		if start == p.i {
			return nil, p.errorf("unexpected %q", c)
		}
		return p.s[start:p.i], nil
	}
}

func (p *zonParser) ident() string {
	if strings.HasPrefix(p.s[p.i:], "@\"") {
		p.i++
		s, _ := p.str()
		return s
	}
	start := p.i
	for p.i < len(p.s) && (p.s[p.i] == '_' || p.s[p.i] >= '0' && p.s[p.i] <= '9' || p.s[p.i]|0x20 >= 'a' && p.s[p.i]|0x20 <= 'z') {
		p.i++
	}
	return p.s[start:p.i]
}

func (p *zonParser) str() (string, error) {
	start := p.i
	p.i++
	for p.i < len(p.s) && p.s[p.i] != '"' {
		if p.s[p.i] == '\\' {
			p.i++
		}
		p.i++
	}
	if p.i >= len(p.s) {
		return "", p.errorf("unterminated string")
	}
	p.i++
	s, err := strconv.Unquote(p.s[start:p.i])
	if err != nil {
		return "", p.errorf("string %s: %v", p.s[start:p.i], err)
	}
	return s, nil
}

// container reads the rest of .{ ... }: a struct of .field = value, or a list of values.
func (p *zonParser) container() (any, error) {
	fields := map[string]any{}
	var list []any
	for {
		p.space()
		if p.i < len(p.s) && p.s[p.i] == '}' {
			p.i++
			if len(fields) > 0 {
				return fields, nil
			}
			if list == nil {
				return map[string]any{}, nil
			}
			return list, nil
		}
		save := p.i
		if p.i < len(p.s) && p.s[p.i] == '.' && !strings.HasPrefix(p.s[p.i:], ".{") {
			p.i++
			name := p.ident()
			p.space()
			if p.i < len(p.s) && p.s[p.i] == '=' {
				p.i++
				v, err := p.value()
				if err != nil {
					return nil, err
				}
				fields[name] = v
				goto next
			}
			p.i = save
		}
		{
			v, err := p.value()
			if err != nil {
				return nil, err
			}
			list = append(list, v)
		}
	next:
		p.space()
		if p.i < len(p.s) && p.s[p.i] == ',' {
			p.i++
		} else if p.i >= len(p.s) || p.s[p.i] != '}' {
			return nil, p.errorf("want , or }")
		}
	}
}
