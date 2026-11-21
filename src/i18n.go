package main

import (
	"bytes"
	"embed"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"unicode"
)

// Localization. i18n/<locale>/ui.json holds the manager page strings for the browser
// runtime (ui/opx-i18n.js), served together as /i18n.js. API messages are written in
// Simplified Chinese in the Go source; i18n/en/server.json maps them to English, chosen
// per request from Accept-Language (the pages send the language the user picked).
//
//go:embed i18n/en/ui.json i18n/zh-CN/ui.json i18n/en/server.json
var i18nFiles embed.FS

var (
	i18nScript      = buildI18nScript()
	englishMessages = loadMessageCatalog("i18n/en/server.json")
)

func buildI18nScript() []byte {
	dictionaries := map[string]json.RawMessage{}
	for _, locale := range []string{"en", "zh-CN"} {
		data, err := i18nFiles.ReadFile("i18n/" + locale + "/ui.json")
		if err != nil {
			panic(err)
		}
		var compact bytes.Buffer
		if err := json.Compact(&compact, data); err != nil {
			panic("i18n/" + locale + "/ui.json: " + err.Error())
		}
		dictionaries[locale] = compact.Bytes()
	}
	data, _ := json.Marshal(dictionaries)
	return append(append([]byte("opxI18n.register("), data...), ");\n"...)
}

type messagePattern struct {
	match    *regexp.Regexp
	names    []string
	template string
}

type messageCatalog struct {
	exact    map[string]string
	patterns []messagePattern
}

var placeholder = regexp.MustCompile(`\{(\w+)\}`)

// loadMessageCatalog reads source → translation pairs. Keys with {name} placeholders
// match messages built at runtime; the captured parts are translated too.
func loadMessageCatalog(path string) *messageCatalog {
	data, err := i18nFiles.ReadFile(path)
	if err != nil {
		panic(err)
	}
	entries := map[string]string{}
	if err := json.Unmarshal(data, &entries); err != nil {
		panic(path + ": " + err.Error())
	}
	catalog := &messageCatalog{exact: map[string]string{}}
	for source, target := range entries {
		if !placeholder.MatchString(source) {
			catalog.exact[source] = target
			continue
		}
		pattern, names, last := "^", []string{}, 0
		for _, at := range placeholder.FindAllStringSubmatchIndex(source, -1) {
			pattern += regexp.QuoteMeta(source[last:at[0]]) + "(.+?)"
			names = append(names, source[at[2]:at[3]])
			last = at[1]
		}
		pattern += regexp.QuoteMeta(source[last:]) + "$"
		catalog.patterns = append(catalog.patterns, messagePattern{regexp.MustCompile(pattern), names, target})
	}
	return catalog
}

// translate returns the English message, or the input when it has no translation.
// Messages joined with " · " are translated part by part.
func (c *messageCatalog) translate(message string) string {
	if target, ok := c.exact[message]; ok {
		return target
	}
	for _, p := range c.patterns {
		if match := p.match.FindStringSubmatch(message); match != nil {
			out := p.template
			for i, name := range p.names {
				out = strings.ReplaceAll(out, "{"+name+"}", c.translate(match[i+1]))
			}
			return out
		}
	}
	if parts := strings.Split(message, " · "); len(parts) > 1 {
		for i, part := range parts {
			parts[i] = c.translate(part)
		}
		return strings.Join(parts, " · ")
	}
	return message
}

// prefersEnglish follows the first Chinese or non-Chinese language in Accept-Language.
// Without the header the source (Chinese) messages are kept for existing API clients.
func prefersEnglish(r *http.Request) bool {
	for _, part := range strings.Split(r.Header.Get("Accept-Language"), ",") {
		tag := strings.ToLower(strings.TrimSpace(strings.SplitN(part, ";", 2)[0]))
		if tag == "" || tag == "*" {
			continue
		}
		return !strings.HasPrefix(tag, "zh")
	}
	return false
}

// localeWriter carries the request language to reply.
type localeWriter struct {
	http.ResponseWriter
	english bool
}

var localizedFields = map[string]bool{"message": true, "detail": true, "error": true}

func hasHan(text string) bool {
	for _, r := range text {
		if unicode.Is(unicode.Han, r) {
			return true
		}
	}
	return false
}

// localizeJSON translates Chinese message/detail/error strings anywhere in a JSON body.
func localizeJSON(data []byte) []byte {
	if !bytes.ContainsFunc(data, func(r rune) bool { return unicode.Is(unicode.Han, r) }) {
		return data
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if decoder.Decode(&value) != nil {
		return data
	}
	var walk func(any) any
	walk = func(node any) any {
		switch v := node.(type) {
		case map[string]any:
			for key, item := range v {
				if text, ok := item.(string); ok && localizedFields[key] && hasHan(text) {
					v[key] = englishMessages.translate(text)
				} else {
					v[key] = walk(item)
				}
			}
		case []any:
			for i, item := range v {
				v[i] = walk(item)
			}
		}
		return node
	}
	out, err := json.Marshal(walk(value))
	if err != nil {
		return data
	}
	return out
}
