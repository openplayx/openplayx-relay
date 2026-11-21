# i18n

Strings for the web manager, in English (`en`) and Simplified Chinese (`zh-CN`).

```
i18n/
  en/ui.json        page strings (English)
  zh-CN/ui.json     page strings (Simplified Chinese)
  en/server.json    English for API messages
```

- `ui.json` is embedded in the binary and served as `/i18n.js`, which registers both
  languages with the UI kit runtime `opx-i18n.js`. Pages pick the language from `?lang=`,
  then `localStorage["opx-lang"]`, then the browser, defaulting to English; the EN / 中文
  button in the header switches in place. Static markup uses `data-i18n="key"` /
  `data-i18n-attr="placeholder:key"`, scripts call `t('key', {vars})`.
- API messages are written in Simplified Chinese in the Go source. `en/server.json` maps
  each one to English; keys with `{name}` placeholders match messages built at runtime,
  and parts joined with ` · ` are translated one by one. The server answers in English when
  the request's `Accept-Language` prefers a non-Chinese language (the pages send the user's
  choice); without the header it keeps the Chinese source text.
- `go test` checks that both `ui.json` files have the same keys and placeholders, that every
  key the pages use exists, and that every Chinese message in the Go source has an English
  translation. Add the English and Chinese text together.
