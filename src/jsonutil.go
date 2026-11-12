package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ConfigError is a user-facing error: a stable code, a message that never
// contains secrets, and the HTTP status the management API answers with.
type ConfigError struct {
	Code    string
	Message string
	Status  int
}

func (e *ConfigError) Error() string { return e.Message }

func cfgErr(code, message string, status ...int) *ConfigError {
	value := 400
	if len(status) > 0 {
		value = status[0]
	}
	return &ConfigError{Code: code, Message: message, Status: value}
}

type obj = map[string]any

// decodeJSON keeps numbers as json.Number so integers round-trip exactly and
// floats can be told apart from integers, like Python's int/float types.
func decodeJSON(data []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("trailing data after JSON value")
	}
	return value, nil
}

func encodeJSON(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// atomicWrite writes private JSON through a same-directory temporary file,
// fsyncs it, renames it into place and fsyncs the directory.
func atomicWrite(path string, value any) error {
	data, err := encodeJSON(value)
	if err != nil {
		return err
	}
	return atomicBytes(path, data)
}

func atomicBytes(path string, data []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(directory, "."+filepath.Base(path)+"-")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Chmod(name, 0o600); err != nil {
		return err
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	return syncDir(directory)
}

func syncDir(directory string) error {
	descriptor, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer descriptor.Close()
	return descriptor.Sync()
}

func readJSON(path string) (any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, cfgErr("invalidFile", "配置文件损坏或不可读，原文件已保留。", 409)
	}
	value, err := decodeJSON(data)
	if err != nil {
		return nil, cfgErr("invalidFile", "配置文件损坏或不可读，原文件已保留。", 409)
	}
	return value, nil
}

func readObj(path string) (obj, error) {
	value, err := readJSON(path)
	if err != nil {
		return nil, err
	}
	result, ok := value.(obj)
	if !ok {
		return nil, cfgErr("invalidFile", "配置文件损坏或不可读，原文件已保留。", 409)
	}
	return result, nil
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// clone deep-copies a JSON value and normalises Go numbers to json.Number.
func clone(value any) any {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	result, err := decodeJSON(data)
	if err != nil {
		panic(err)
	}
	return result
}

func cloneObj(value obj) obj { return clone(value).(obj) }

// canonical gives equal strings for equal JSON values (map keys are sorted).
func canonical(value any) string {
	data, _ := json.Marshal(value)
	return string(data)
}

func keysOf(value obj) []string {
	result := make([]string, 0, len(value))
	for key := range value {
		result = append(result, key)
	}
	return result
}

func checkKeys(value any, allowed, required []string) error {
	fields, ok := value.(obj)
	if !ok {
		return cfgErr("invalidFields", "配置字段缺失或包含未知字段。")
	}
	permitted := map[string]bool{}
	for _, key := range allowed {
		permitted[key] = true
	}
	for key := range fields {
		if !permitted[key] {
			return cfgErr("invalidFields", "配置字段缺失或包含未知字段。")
		}
	}
	for _, key := range required {
		if _, ok := fields[key]; !ok {
			return cfgErr("invalidFields", "配置字段缺失或包含未知字段。")
		}
	}
	return nil
}

func intValue(value any) (int64, bool) {
	switch number := value.(type) {
	case json.Number:
		result, err := strconv.ParseInt(string(number), 10, 64)
		return result, err == nil
	case int:
		return int64(number), true
	case int64:
		return number, true
	}
	return 0, false
}

func text(value any, field string) (string, error) {
	result, ok := value.(string)
	if !ok || strings.TrimSpace(result) == "" || utf8.RuneCountInString(result) > 256 {
		return "", cfgErr("invalidField", field+" 无效。")
	}
	for _, character := range result {
		if character < 32 {
			return "", cfgErr("invalidField", field+" 无效。")
		}
	}
	return result, nil
}

func port(value any) (int, error) {
	number, ok := intValue(value)
	if !ok || number < 1 || number > 65535 {
		return 0, cfgErr("invalidPort", "端口须为 1–65535。")
	}
	return int(number), nil
}

func host(value any) (string, error) {
	result, err := text(value, "主机")
	if err != nil {
		return "", err
	}
	if _, err := netip.ParseAddr(result); err == nil {
		return result, nil
	}
	if len(result) > 253 {
		return "", cfgErr("invalidHost", "请输入 IP 或主机名，不包含 URL、路径或凭据。")
	}
	for _, character := range result {
		if character > unicode.MaxASCII || !(isAlnum(character) || character == '.' || character == '-') {
			return "", cfgErr("invalidHost", "请输入 IP 或主机名，不包含 URL、路径或凭据。")
		}
	}
	return result, nil
}

func identifier(value any) (string, error) {
	result, err := text(value, "ID")
	if err != nil {
		return "", err
	}
	for _, character := range result {
		if character > unicode.MaxASCII || !(isAlnum(character) || character == '-' || character == '_') {
			return "", cfgErr("invalidId", "ID 仅支持字母、数字、短横线、下划线。")
		}
	}
	return result, nil
}

func isAlnum(character rune) bool {
	return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9')
}

// lanNetworks are explicit home ranges; "private" in Go and Python also
// includes reserved and documentation addresses, which are not accepted.
var lanNetworks = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("fe80::/10"),
}

func isLANAddress(value string) bool {
	address, err := netip.ParseAddr(value)
	if err != nil {
		return false
	}
	address = address.Unmap().WithZone("")
	if address.IsLoopback() {
		return true
	}
	for _, network := range lanNetworks {
		if network.Contains(address) {
			return true
		}
	}
	return false
}

// parseUUID accepts the same spellings as Python's uuid.UUID: canonical,
// braced, urn:uuid: prefixed and plain 32 hexadecimal digits.
func parseUUID(value any) bool {
	input, ok := value.(string)
	if !ok {
		return false
	}
	input = strings.ReplaceAll(strings.ReplaceAll(input, "urn:", ""), "uuid:", "")
	input = strings.Trim(input, "{}")
	input = strings.ReplaceAll(input, "-", "")
	if len(input) != 32 {
		return false
	}
	_, err := hex.DecodeString(input)
	return err == nil
}

func randomBytes(size int) []byte {
	buffer := make([]byte, size)
	if _, err := rand.Read(buffer); err != nil {
		panic(err)
	}
	return buffer
}

func tokenURLSafe(size int) string { return base64.RawURLEncoding.EncodeToString(randomBytes(size)) }

func tokenHex(size int) string { return hex.EncodeToString(randomBytes(size)) }
