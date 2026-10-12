// Modified for efrgdgr0024345/dnscheck on 2026-10-12.
// Original project by Brian Shea and contributors; see COPYRIGHT, LICENSE and CREDITS.md.

package httputil

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"
)

const MaxRequestBodyBytes = 16 << 10
const MaxRequestQueryBytes = 4096
const MaxRequestFields = 16

var (
	ErrAmbiguousValues      = errors.New("duplicate request values are not permitted")
	ErrValueUnexpectedType  = errors.New("request values must be strings")
	ErrBodyTooLarge         = errors.New("request body exceeds 16 KiB")
	ErrUnsupportedMediaType = errors.New("use application/json or application/x-www-form-urlencoded")
	ErrQueryCredential      = errors.New("credentials in URLs are disabled; use Authorization: Bearer")
	ErrInvalidAuthorization = errors.New("invalid or ambiguous Authorization header")
)

type JSONObject map[string]interface{}

type RequestValues struct {
	req     *http.Request
	body    []byte
	form    url.Values
	jsonObj JSONObject
	query   url.Values
	values  map[string]string
	err     error
}

// ParseRequest parses the complete small request once. Any malformed input,
// duplicate field (including identical duplicates), or non-string JSON value
// makes the entire request invalid rather than silently discarding input.
func ParseRequest(req *http.Request) *RequestValues {
	p := &RequestValues{req: req, values: make(map[string]string), query: make(url.Values), form: make(url.Values), jsonObj: make(JSONObject)}
	p.err = p.parse()
	return p
}
func (p *RequestValues) parse() error {
	if len(p.req.URL.RawQuery) > MaxRequestQueryBytes {
		return errors.New("query string exceeds 4 KiB")
	}
	query, err := url.ParseQuery(p.req.URL.RawQuery)
	if err != nil {
		return errors.New("malformed query string")
	}
	p.query = query
	if err = p.addValues(query); err != nil {
		return err
	}
	if p.req.ContentLength > MaxRequestBodyBytes {
		return ErrBodyTooLarge
	}
	if p.req.Body != nil {
		p.body, err = io.ReadAll(io.LimitReader(p.req.Body, MaxRequestBodyBytes+1))
		if err != nil {
			var sizeError *http.MaxBytesError
			if errors.As(err, &sizeError) {
				return ErrBodyTooLarge
			}
			return errors.New("could not read request body")
		}
		if len(p.body) > MaxRequestBodyBytes {
			return ErrBodyTooLarge
		}
	}
	if len(p.body) == 0 {
		return nil
	}
	if p.req.Method == http.MethodGet || p.req.Method == http.MethodHead {
		return errors.New("read requests must not contain a body")
	}
	if !utf8.Valid(p.body) {
		return errors.New("request body is not valid UTF-8")
	}
	contentType := p.req.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/x-www-form-urlencoded"
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return ErrUnsupportedMediaType
	}
	switch mediaType {
	case "application/x-www-form-urlencoded":
		p.form, err = url.ParseQuery(string(p.body))
		if err != nil {
			return errors.New("malformed form body")
		}
		return p.addValues(p.form)
	case "application/json":
		dec := json.NewDecoder(bytes.NewReader(p.body))
		token, err := dec.Token()
		if err != nil || token != json.Delim('{') {
			return errors.New("JSON body must be an object")
		}
		for dec.More() {
			token, err = dec.Token()
			if err != nil {
				return errors.New("malformed JSON body")
			}
			key, ok := token.(string)
			if !ok {
				return errors.New("malformed JSON key")
			}
			valueToken, valueErr := dec.Token()
			value, isString := valueToken.(string)
			if valueErr != nil || !isString {
				return ErrValueUnexpectedType
			}
			if _, exists := p.values[key]; exists {
				return ErrAmbiguousValues
			}
			if len(p.values) >= MaxRequestFields {
				return errors.New("too many request fields")
			}
			p.values[key] = value
			p.jsonObj[key] = value
		}
		if _, err = dec.Token(); err != nil {
			return errors.New("malformed JSON body")
		}
		if _, err = dec.Token(); err != io.EOF {
			return errors.New("unexpected data after JSON object")
		}
		return nil
	default:
		return ErrUnsupportedMediaType
	}
}
func (p *RequestValues) addValues(values url.Values) error {
	for key, vs := range values {
		if len(vs) != 1 {
			return ErrAmbiguousValues
		}
		if _, exists := p.values[key]; exists {
			return ErrAmbiguousValues
		}
		if len(p.values) >= MaxRequestFields {
			return errors.New("too many request fields")
		}
		p.values[key] = vs[0]
	}
	return nil
}
func (p *RequestValues) Validate(allowed ...string) error {
	if p.err != nil {
		return p.err
	}
	set := make(map[string]bool, len(allowed))
	for _, key := range allowed {
		set[key] = true
	}
	for key := range p.values {
		if !set[key] {
			return errors.New("unknown request field")
		}
	}
	return nil
}
func (p *RequestValues) Body() ([]byte, error)     { return bytes.Clone(p.body), p.err }
func (p *RequestValues) BodyText() (string, error) { return string(p.body), p.err }
func (p *RequestValues) ContentType() string {
	t, _, _ := mime.ParseMediaType(p.req.Header.Get("Content-Type"))
	return t
}
func (p *RequestValues) Form() (url.Values, error)       { return p.form, p.err }
func (p *RequestValues) JSONObject() (JSONObject, error) { return p.jsonObj, p.err }
func (p *RequestValues) Query() url.Values               { return p.query }
func (p *RequestValues) Values(key string) ([]interface{}, error) {
	if p.err != nil {
		return nil, p.err
	}
	if v, ok := p.values[key]; ok {
		return []interface{}{v}, nil
	}
	return nil, nil
}
func (p *RequestValues) GetString(key string) (string, error) {
	if p.err != nil {
		return "", p.err
	}
	return p.values[key], nil
}

// Credential accepts one Bearer token or one body field for clients migrating
// from upstream. URL credentials and multiple sources are always rejected.
func (p *RequestValues) Credential(field string) (string, error) {
	if p.err != nil {
		return "", p.err
	}
	if _, ok := p.query[field]; ok {
		return "", ErrQueryCredential
	}
	headers := p.req.Header.Values("Authorization")
	value, bodyPresent := p.values[field]
	if len(headers) == 0 {
		return value, nil
	}
	if len(headers) != 1 || bodyPresent {
		return "", ErrInvalidAuthorization
	}
	parts := strings.Fields(headers[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || strings.Contains(parts[1], ",") {
		return "", ErrInvalidAuthorization
	}
	return parts[1], nil
}

// IsRandomToken verifies only canonical encoding and length. No format check
// can prove randomness: generate tokens using NewRandomToken/crypto.getRandomValues.
func IsRandomToken(token string) bool {
	if len(token) != 43 {
		return false
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(token)
	return err == nil && len(b) == 32 && base64.RawURLEncoding.EncodeToString(b) == token
}
func NewRandomToken() string {
	var b [32]byte
	rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}
func RequestError(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	if errors.Is(err, ErrBodyTooLarge) {
		status = http.StatusRequestEntityTooLarge
	}
	if errors.Is(err, ErrUnsupportedMediaType) {
		status = http.StatusUnsupportedMediaType
	}
	http.Error(w, err.Error(), status)
}
func NoStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Add("Vary", "Authorization")
}
func RequiredString(p *RequestValues, field string) (string, error) {
	value, err := p.GetString(field)
	if err == nil && value == "" {
		err = fmt.Errorf("must specify %q", field)
	}
	return value, err
}
