package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/scrypt"
)

type session struct {
	csrf      string
	expiresAt float64
}

// Admin handles the local administrator identity, which is independent of
// the App, Home and frp credentials. Parameters match the stored admin.json.
type Admin struct {
	dir      string
	now      func() float64
	mu       sync.Mutex
	sessions map[string]session
	failures map[string][]float64
}

func wallClock() float64 { return float64(time.Now().UnixNano()) / 1e9 }

func NewAdmin(directory string) *Admin {
	return &Admin{dir: directory, now: wallClock, sessions: map[string]session{}, failures: map[string][]float64{}}
}

func (a *Admin) file(name string) string { return filepath.Join(a.dir, name) }

func adminDigest(password string, salt []byte) (string, error) {
	digest, err := scrypt.Key([]byte(password), salt, 16384, 8, 1, 64)
	return hex.EncodeToString(digest), err
}

func sha256Hex(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

// bootstrap issues a 15 minute local credential while no administrator
// password exists. There is no public default password.
func (a *Admin) bootstrap(renew bool) error {
	if exists(a.file("admin.json")) && !renew {
		return nil
	}
	if exists(a.file("bootstrap.json")) && !renew {
		current, err := readObj(a.file("bootstrap.json"))
		if err != nil {
			return err
		}
		if expires, ok := numberValue(current["expiresAt"]); ok && expires > a.now() {
			return nil
		}
	}
	token := tokenURLSafe(32)
	if err := atomicWrite(a.file("bootstrap.json"), obj{"hash": sha256Hex(token), "expiresAt": int64(a.now() + 900)}); err != nil {
		return err
	}
	return writeSynced(a.file("bootstrap-token"), []byte(token+"\n"))
}

func numberValue(value any) (float64, bool) {
	if number, ok := intValue(value); ok {
		return float64(number), true
	}
	return 0, false
}

func (a *Admin) authenticate(passwordValue any, peer string) (string, string, error) {
	password, ok := passwordValue.(string)
	if !ok || utf8.RuneCountInString(password) > 1024 {
		return "", "", cfgErr("loginFailed", "登录失败。", 401)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	recent := []float64{}
	for _, moment := range a.failures[peer] {
		if moment > now-60 {
			recent = append(recent, moment)
		}
	}
	if len(recent) >= 8 {
		return "", "", cfgErr("rateLimited", "登录尝试过多，请稍后重试。", 429)
	}
	valid := false
	if exists(a.file("admin.json")) {
		admin, err := readObj(a.file("admin.json"))
		if err != nil {
			return "", "", err
		}
		salt, _ := hex.DecodeString(stringValue(admin["salt"]))
		digest, err := adminDigest(password, salt)
		if err != nil {
			return "", "", err
		}
		valid = subtle.ConstantTimeCompare([]byte(digest), []byte(stringValue(admin["hash"]))) == 1
	}
	if !valid && exists(a.file("bootstrap.json")) {
		bootstrap, err := readObj(a.file("bootstrap.json"))
		if err != nil {
			return "", "", err
		}
		expires, _ := numberValue(bootstrap["expiresAt"])
		valid = expires > now && subtle.ConstantTimeCompare([]byte(stringValue(bootstrap["hash"])), []byte(sha256Hex(password))) == 1
	}
	if !valid {
		a.failures[peer] = append(recent, now)
		return "", "", cfgErr("loginFailed", "凭据错误或初始化凭据已过期。", 401)
	}
	for token, value := range a.sessions {
		if value.expiresAt <= now {
			delete(a.sessions, token)
		}
	}
	token, csrf := tokenURLSafe(32), tokenURLSafe(32)
	a.sessions[token] = session{csrf: csrf, expiresAt: now + 1800}
	return token, csrf, nil
}

func stringValue(value any) string {
	result, _ := value.(string)
	return result
}

func (a *Admin) session(token string) (session, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	value, ok := a.sessions[token]
	if !ok || value.expiresAt < a.now() {
		delete(a.sessions, token)
		return session{}, cfgErr("authenticationRequired", "请先登录管理页面。", 401)
	}
	return value, nil
}

func (a *Admin) logout(token string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.sessions, token)
}

func (a *Admin) setPassword(passwordValue any) error {
	password, ok := passwordValue.(string)
	length := utf8.RuneCountInString(password)
	if !ok || length < 16 || length > 256 {
		return cfgErr("weakPassword", "管理员密码须为 16–256 个字符。")
	}
	salt := randomBytes(16)
	digest, err := adminDigest(password, salt)
	if err != nil {
		return err
	}
	if err = atomicWrite(a.file("admin.json"), obj{"salt": hex.EncodeToString(salt), "hash": digest}); err != nil {
		return err
	}
	_ = os.Remove(a.file("bootstrap.json"))
	_ = os.Remove(a.file("bootstrap-token"))
	a.mu.Lock()
	a.sessions = map[string]session{}
	a.mu.Unlock()
	return nil
}
