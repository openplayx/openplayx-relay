package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func flattenKeys(prefix string, node any, out map[string]string) {
	switch v := node.(type) {
	case map[string]any:
		for key, item := range v {
			flattenKeys(prefix+key+".", item, out)
		}
	case string:
		out[strings.TrimSuffix(prefix, ".")] = v
	}
}

func readUI(t *testing.T, locale string) map[string]string {
	t.Helper()
	data, err := os.ReadFile("i18n/" + locale + "/ui.json")
	if err != nil {
		t.Fatal(err)
	}
	var tree any
	if err := json.Unmarshal(data, &tree); err != nil {
		t.Fatal(err)
	}
	keys := map[string]string{}
	flattenKeys("", tree, keys)
	return keys
}

func TestUIDictionariesMatch(t *testing.T) {
	en, zh := readUI(t, "en"), readUI(t, "zh-CN")
	vars := func(text string) string {
		found := placeholder.FindAllString(text, -1)
		sort.Strings(found)
		return strings.Join(found, ",")
	}
	for key, value := range en {
		other, ok := zh[key]
		if !ok {
			t.Errorf("zh-CN/ui.json misses %s", key)
			continue
		}
		if vars(value) != vars(other) {
			t.Errorf("%s: placeholders differ: %q vs %q", key, value, other)
		}
		if hasHan(value) {
			t.Errorf("en/ui.json %s is not English: %q", key, value)
		}
	}
	for key := range zh {
		if _, ok := en[key]; !ok {
			t.Errorf("en/ui.json misses %s", key)
		}
	}
	if script := string(i18nScript); !strings.HasPrefix(script, "opxI18n.register({") || !strings.Contains(script, `"zh-CN":`) {
		t.Fatalf("i18n.js: %.80s", script)
	}
}

// Every key the manager pages use must exist, and no Chinese may remain in them.
func TestWebPagesUseKnownKeys(t *testing.T) {
	en := readUI(t, "en")
	files, _ := filepath.Glob("web/*.js")
	html, _ := filepath.Glob("web/*.html")
	uses := regexp.MustCompile(`\bt\('([\w.]+)'|data-i18n="([\w.]+)"|:([\w]+\.[\w.]+)`)
	for _, name := range append(files, html...) {
		if strings.Contains(name, "opx-") {
			continue
		}
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		for _, line := range strings.Split(text, "\n") {
			if hasHan(strings.ReplaceAll(line, ">中文<", "")) {
				t.Errorf("%s: untranslated text: %.80s", name, line)
			}
		}
		for _, match := range uses.FindAllStringSubmatch(text, -1) {
			key := match[1] + match[2]
			if key == "" {
				if !strings.Contains(match[0], "data-i18n") && !regexp.MustCompile(`data-i18n-attr="[^"]*` + regexp.QuoteMeta(match[3])).MatchString(text) {
					continue
				}
				key = match[3]
			}
			if _, ok := en[key]; !ok {
				t.Errorf("%s uses unknown key %s", name, key)
			}
		}
	}
}

// Every Chinese message in the Go source has an English translation.
func TestServerMessagesHaveEnglish(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	literal := regexp.MustCompile(`"((?:[^"\\\n]|\\.)*)"`)
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		data, _ := os.ReadFile(name)
		for _, match := range literal.FindAllStringSubmatch(string(data), -1) {
			source := strings.ReplaceAll(match[1], `\"`, `"`)
			if !hasHan(source) {
				continue
			}
			// Fragments are joined with runtime values; build a sample message.
			sample := strings.ReplaceAll(source, "%s", "x")
			if strings.HasSuffix(sample, " ") || strings.HasSuffix(sample, "：") {
				sample += "x"
			}
			if strings.HasPrefix(sample, " ") {
				sample = "x" + sample
			}
			if got := englishMessages.translate(sample); hasHan(got) {
				t.Errorf("%s: no English for %q (got %q)", name, source, got)
			}
		}
	}
}

func TestRepliesFollowAcceptLanguage(t *testing.T) {
	cases := map[string]bool{"": false, "zh-CN,zh;q=0.9": false, "en-US": true, "en-GB,zh;q=0.8": true, "fr-FR": true, "*": false}
	for header, english := range cases {
		r := httptest.NewRequest("GET", "/api/session", nil)
		if header != "" {
			r.Header.Set("Accept-Language", header)
		}
		if prefersEnglish(r) != english {
			t.Errorf("Accept-Language %q: english=%v", header, !english)
		}
	}
	m := &ManagerServer{}
	recorder := httptest.NewRecorder()
	m.reply(&localeWriter{ResponseWriter: recorder, english: true}, 400, obj{"error": "invalidField", "message": "主机 无效。", "items": []any{obj{"detail": "HTTP · 版本 1.2 · mDNS 广播", "port": json.Number("18096")}}}, nil)
	body := recorder.Body.String()
	for _, want := range []string{`"message":"Host is invalid."`, `"detail":"HTTP · version 1.2 · mDNS broadcast"`, `"error":"invalidField"`, `"port":18096`} {
		if !strings.Contains(body, want) {
			t.Errorf("reply %s lacks %s", body, want)
		}
	}
	recorder = httptest.NewRecorder()
	m.reply(recorder, 400, obj{"message": "主机 无效。"}, nil)
	if !strings.Contains(recorder.Body.String(), "主机 无效。") {
		t.Errorf("default reply should keep the source message: %s", recorder.Body.String())
	}
}
