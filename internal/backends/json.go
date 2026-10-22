package backends

import (
	"bytes"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"unicode/utf8"
)

// DecodeJSON preserves integer precision and rejects trailing or invalid UTF-8 input.
func DecodeJSON(data []byte) (any, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("JSON is not valid UTF-8")
	}
	if err := validSurrogates(data); err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, errors.New("multiple JSON values")
		}
		return nil, err
	}
	return v, nil
}

func validSurrogates(b []byte) error {
	for i := 0; i < len(b); i++ {
		if b[i] != '"' {
			continue
		}
		for i++; i < len(b) && b[i] != '"'; i++ {
			if b[i] != '\\' {
				continue
			}
			i++
			if i >= len(b) {
				return errors.New("unterminated JSON escape")
			}
			if b[i] != 'u' {
				continue
			}
			if i+4 >= len(b) {
				return errors.New("short JSON unicode escape")
			}
			u, e := hex4(b[i+1 : i+5])
			if e != nil {
				return e
			}
			i += 4
			if u >= 0xdc00 && u <= 0xdfff {
				return errors.New("unpaired low surrogate in JSON string")
			}
			if u >= 0xd800 && u <= 0xdbff {
				if i+6 >= len(b) || b[i+1] != '\\' || b[i+2] != 'u' {
					return errors.New("unpaired high surrogate in JSON string")
				}
				v, e := hex4(b[i+3 : i+7])
				if e != nil || v < 0xdc00 || v > 0xdfff {
					return errors.New("unpaired high surrogate in JSON string")
				}
				i += 6
			}
		}
	}
	return nil
}
func hex4(b []byte) (uint16, error) {
	var n uint16
	for _, c := range b {
		n <<= 4
		switch {
		case c >= '0' && c <= '9':
			n += uint16(c - '0')
		case c >= 'a' && c <= 'f':
			n += uint16(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			n += uint16(c - 'A' + 10)
		default:
			return 0, errors.New("invalid JSON unicode escape")
		}
	}
	return n, nil
}

func finite(v any) error {
	return finiteReflect(reflect.ValueOf(v), 0, map[visit]bool{})
}

type visit struct {
	typ reflect.Type
	ptr uintptr
}

func finiteReflect(v reflect.Value, depth int, stack map[visit]bool) error {
	if !v.IsValid() {
		return nil
	}
	if depth > 128 {
		return errors.New("JSON value exceeds nesting limit")
	}
	switch v.Kind() {
	case reflect.Interface, reflect.Pointer:
		if v.IsNil() {
			return nil
		}
		if v.Kind() == reflect.Pointer {
			key := visit{v.Type(), v.Pointer()}
			if stack[key] {
				return errors.New("cyclic JSON value")
			}
			stack[key] = true
			defer delete(stack, key)
		}
		return finiteReflect(v.Elem(), depth+1, stack)
	case reflect.String:
		if !utf8.ValidString(v.String()) {
			return errors.New("invalid UTF-8 string")
		}
	case reflect.Float32, reflect.Float64:
		if math.IsNaN(v.Float()) || math.IsInf(v.Float(), 0) {
			return errors.New("non-finite JSON number")
		}
	case reflect.Map:
		if v.IsNil() {
			return nil
		}
		key := visit{v.Type(), v.Pointer()}
		if stack[key] {
			return errors.New("cyclic JSON value")
		}
		stack[key] = true
		defer delete(stack, key)
		it := v.MapRange()
		for it.Next() {
			k := it.Key()
			if k.Kind() == reflect.String && !utf8.ValidString(k.String()) {
				return errors.New("invalid UTF-8 map key")
			}
			if k.CanInterface() && k.Type().Implements(reflect.TypeOf((*encoding.TextMarshaler)(nil)).Elem()) {
				text, err := k.Interface().(encoding.TextMarshaler).MarshalText()
				if err != nil {
					return err
				}
				if !utf8.Valid(text) {
					return errors.New("invalid UTF-8 marshaled map key")
				}
			}
			if err := finiteReflect(it.Value(), depth+1, stack); err != nil {
				return err
			}
		}
	case reflect.Slice:
		if v.IsNil() {
			return nil
		}
		key := visit{v.Type(), v.Pointer()}
		if key.ptr != 0 {
			if stack[key] {
				return errors.New("cyclic JSON value")
			}
			stack[key] = true
			defer delete(stack, key)
		}
		fallthrough
	case reflect.Array:
		for i := 0; i < v.Len(); i++ {
			if err := finiteReflect(v.Index(i), depth+1, stack); err != nil {
				return err
			}
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).PkgPath == "" {
				if err := finiteReflect(v.Field(i), depth+1, stack); err != nil {
					return err
				}
			}
		}
	case reflect.Invalid:
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr, reflect.Bool:
	default:
		if v.CanInterface() {
			if n, ok := v.Interface().(json.Number); ok {
				if _, err := n.Int64(); err != nil {
					f, ferr := n.Float64()
					if ferr != nil || math.IsInf(f, 0) || math.IsNaN(f) {
						return fmt.Errorf("invalid JSON number %q", n)
					}
				}
			}
		}
	}
	return nil
}

func EncodeJSON(v any, pretty, sortKeys bool, newline bool) ([]byte, error) {
	if err := finite(v); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if pretty {
		e.SetIndent("", "  ")
	}
	if err := e.Encode(v); err != nil {
		return nil, err
	}
	out := unescapeLineSeparators(bytes.TrimSuffix(b.Bytes(), []byte("\n")))
	if _, err := DecodeJSON(out); err != nil {
		return nil, fmt.Errorf("invalid emitted JSON: %w", err)
	}
	if newline {
		out = append(out, '\n')
	}
	_ = sortKeys // encoding/json emits map keys in lexical order.
	return append([]byte(nil), out...), nil
}

func unescapeLineSeparators(src []byte) []byte {
	var out bytes.Buffer
	inString := false
	for i := 0; i < len(src); i++ {
		c := src[i]
		if !inString {
			out.WriteByte(c)
			if c == '"' {
				inString = true
			}
			continue
		}
		if c == '"' {
			inString = false
			out.WriteByte(c)
			continue
		}
		if c == '\\' && i+1 < len(src) {
			if i+5 < len(src) && src[i+1] == 'u' && string(src[i+2:i+6]) == "2028" {
				out.WriteRune('\u2028')
				i += 5
				continue
			}
			if i+5 < len(src) && src[i+1] == 'u' && string(src[i+2:i+6]) == "2029" {
				out.WriteRune('\u2029')
				i += 5
				continue
			}
			out.WriteByte(c)
			i++
			out.WriteByte(src[i])
			continue
		}
		out.WriteByte(c)
	}
	return out.Bytes()
}
