package core

import (
	"reflect"
	"strings"
)

type FieldSchema struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Optional bool   `json:"optional"`
}

type OpSchema struct {
	Op     string        `json:"op"`
	Fields []FieldSchema `json:"fields"`
}

func SchemaOf(op string, t reflect.Type) OpSchema {
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	s := OpSchema{Op: op, Fields: []FieldSchema{}}
	if t.Kind() != reflect.Struct {
		return s
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name, opt := jsonField(f)
		if name == "-" {
			continue
		}
		s.Fields = append(s.Fields, FieldSchema{Name: name, Type: renderType(f.Type), Optional: opt})
	}
	return s
}

func jsonField(f reflect.StructField) (name string, optional bool) {
	tag := f.Tag.Get("json")
	if tag == "" {
		return f.Name, false
	}
	parts := strings.Split(tag, ",")
	name = parts[0]
	if name == "" {
		name = f.Name
	}
	for _, p := range parts[1:] {
		if p == "omitempty" {
			optional = true
		}
	}
	return name, optional
}

func renderType(t reflect.Type) string {
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.String:
		return "string"
	case reflect.Bool:
		return "bool"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return "int"
	case reflect.Float32, reflect.Float64:
		return "number"
	case reflect.Slice:
		switch t.Elem().Kind() {
		case reflect.Uint8:
			return "bytes"
		case reflect.String:
			return "string[]"
		default:
			return "json"
		}
	default:
		return "json"
	}
}
