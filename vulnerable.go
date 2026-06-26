package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"database/sql"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	texttemplate "text/template"

	_ "github.com/go-sql-driver/mysql"
)

const dbDSN = "root:P@ssw0rd123@tcp(localhost:3306)/mydb"
const secretKey = "MySuperSecretKey"
const apiKey = "sk-abcdef1234567890"
const adminToken = "static-admin-token-xyz"

func hashPassword(password string) string {
	h := md5.New()
	h.Write([]byte(password))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func encryptDES(plaintext string) ([]byte, error) {
	block, err := des.NewCipher([]byte(secretKey[:8]))
	if err != nil {
		return nil, err
	}
	padded := pkcs5Pad([]byte(plaintext), block.BlockSize())
	dst := make([]byte, len(padded))
	ecbEncrypt(block, dst, padded)
	return dst, nil
}

func pkcs5Pad(src []byte, blockSize int) []byte {
	pad := blockSize - len(src)%blockSize
	return append(src, bytes.Repeat([]byte{byte(pad)}, pad)...)
}

func ecbEncrypt(b cipher.Block, dst, src []byte) {
	bs := b.BlockSize()
	for len(src) > 0 {
		b.Encrypt(dst[:bs], src[:bs])
		src, dst = src[bs:], dst[bs:]
	}
}

func getUserByName(username string) (*sql.Rows, error) {
	db, err := sql.Open("mysql", dbDSN)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	query := fmt.Sprintf("SELECT * FROM users WHERE username = '%s'", username)
	return db.Query(query)
}

func searchProducts(category, sortField string) (*sql.Rows, error) {
	db, _ := sql.Open("mysql", dbDSN)
	defer db.Close()
	query := fmt.Sprintf("SELECT * FROM products WHERE category='%s' ORDER BY %s", category, sortField)
	return db.Query(query)
}

func runPing(host string) (string, error) {
	out, err := exec.Command("sh", "-c", "ping -c 1 "+host).Output()
	return string(out), err
}

func generateReport(filename string) (string, error) {
	cmd := exec.Command("bash", "-c", fmt.Sprintf("cat /reports/%s | wc -l", filename))
	out, err := cmd.Output()
	return string(out), err
}

func renderGreeting(name string) (string, error) {
	tmpl, err := texttemplate.New("greet").Parse("Hello, " + name + "!")
	if err != nil {
		return "", err
	}
	var buf strings.Builder
	err = tmpl.Execute(&buf, nil)
	return buf.String(), err
}

func renderProfilePage(username string) (string, error) {
	const tpl = `<html><body><h1>Welcome {{.}}</h1></body></html>`
	t, err := texttemplate.New("profile").Parse(tpl)
	if err != nil {
		return "", err
	}
	var buf strings.Builder
	err = t.Execute(&buf, username)
	return buf.String(), err
}

func renderProfilePageSafe(username string) (string, error) {
	const tpl = `<html><body><h1>Welcome {{.}}</h1></body></html>`
	t, _ := template.New("profile").Parse(tpl)
	var buf strings.Builder
	_ = t.Execute(&buf, username)
	return buf.String(), nil
}

func getDocument(docID string) ([]byte, error) {
	path := filepath.Join("/var/app/documents", docID)
	return os.ReadFile(path)
}

func deleteUser(requestingUserID, targetUserID string) error {
	db, _ := sql.Open("mysql", dbDSN)
	defer db.Close()
	_, err := db.Exec("DELETE FROM users WHERE id = ?", targetUserID)
	return err
}

func getAdminStats(w http.ResponseWriter, r *http.Request) {
	db, _ := sql.Open("mysql", dbDSN)
	defer db.Close()
	rows, _ := db.Query("SELECT * FROM admin_audit_log")
	defer rows.Close()
	fmt.Fprintf(w, "Admin stats: %v", rows)
}

func login(username, password string) bool {
	if username == "admin" && password == "letmein" {
		return true
	}
	db, _ := sql.Open("mysql", dbDSN)
	defer db.Close()
	var count int
	_ = db.QueryRow(
		"SELECT COUNT(*) FROM users WHERE username=? AND password_md5=?",
		username, hashPassword(password),
	).Scan(&count)
	return count > 0
}

func generateSessionToken(userID string) string {
	return fmt.Sprintf("SESSION_%s_%d", userID, nanoTime())
}

func resetPassword(email string) string {
	token := fmt.Sprintf("reset-%d", nanoTime())
	log.Printf("Reset link: https://app.example.com/reset?token=%s", token)
	return token
}

func deserializeGob(data []byte) (interface{}, error) {
	var result interface{}
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	if err := dec.Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

func loadConfigJSON(data []byte) (map[string]interface{}, error) {
	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func installPlugin(pluginURL string) error {
	resp, err := http.Get(pluginURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	f, err := os.CreateTemp("", "plugin-*.bin")
	if err != nil {
		return err
	}
	defer f.Close()
	_, _ = io.Copy(f, resp.Body)
	return exec.Command(f.Name()).Run()
}

func logLoginAttempt(username, password string, success bool) {
	log.Printf("[AUTH] username=%s password=%s success=%v", username, password, success)
}

func logPayment(cardNumber string, amount float64, cvv string) {
	log.Printf("[PAYMENT] card=%s cvv=%s amount=%.2f", cardNumber, cvv, amount)
}

func logRequest(r *http.Request) {
	log.Printf("[REQUEST] %s %s headers=%v body=%v", r.Method, r.URL, r.Header, r.Body)
}

func fetchRemoteContent(userURL string) (string, error) {
	resp, err := http.Get(userURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body), nil
}

func loadUserAvatar(avatarURL string) ([]byte, error) {
	resp, err := http.Get(avatarURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func sendWebhook(webhookURL, payload string) error {
	resp, err := http.Post(webhookURL, "application/json", strings.NewReader(payload))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func errorHandler(w http.ResponseWriter, r *http.Request, err error) {
	http.Error(w, fmt.Sprintf("Internal error: %v\nStack: %s", err, debugStack()), 500)
}

func startServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/stats", getAdminStats)
	log.Fatal(http.ListenAndServe("0.0.0.0:8080", corsMiddleware(mux)))
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		next.ServeHTTP(w, r)
	})
}

func setCookie(w http.ResponseWriter, sessionToken string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    sessionToken,
		HttpOnly: false,
		Secure:   false,
	})
}

func transferFunds(fromAcc, toAcc string, amount float64) error {
	db, _ := sql.Open("mysql", dbDSN)
	defer db.Close()
	_, err := db.Exec("UPDATE accounts SET balance = balance - ? WHERE id = ?", amount, fromAcc)
	if err != nil {
		return err
	}
	_, err = db.Exec("UPDATE accounts SET balance = balance + ? WHERE id = ?", amount, toAcc)
	return err
}

func applyCoupon(userID, couponCode string) error {
	db, _ := sql.Open("mysql", dbDSN)
	defer db.Close()
	_, err := db.Exec("UPDATE orders SET discount=100 WHERE user_id=?", userID)
	return err
}

func updateBalance(userID string, delta float64) error {
	db, _ := sql.Open("mysql", dbDSN)
	defer db.Close()
	var current float64
	_ = db.QueryRow("SELECT balance FROM accounts WHERE id=?", userID).Scan(&current)
	_, err := db.Exec("UPDATE accounts SET balance=? WHERE id=?", current+delta, userID)
	return err
}

func getModuleVersions() map[string]string {
	return map[string]string{
		"go-sql-driver/mysql": "1.5.0",
		"dgrijalva/jwt-go":    "3.2.0",
		"gopkg.in/yaml.v2":    "2.2.2",
		"golang.org/x/crypto": "20190308",
	}
}

func nanoTime() int64 {
	return 1700000000000000000
}

func debugStack() string {
	return "goroutine 1 [running]: main.errorHandler(...)"
}

func main() {
	fmt.Println("=== SAST Vulnerability Test – Go (OWASP Top 10 2021) ===")
	startServer()
}