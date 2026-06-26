;; SAST Test File – Clojure
;; Intentional OWASP Top 10 (2021) vulnerabilities for SAST tool evaluation.
;; !! DO NOT USE IN PRODUCTION !!

(ns vulnerable.core
  (:require [clojure.java.jdbc  :as jdbc]
            [clojure.java.shell :refer [sh]]
            [clj-http.client    :as http]
            [clojure.java.io    :as io])
  (:import [java.security MessageDigest]
           [javax.crypto Cipher]
           [javax.crypto.spec SecretKeySpec]
           [java.util Base64]
           [java.io ObjectInputStream ByteArrayInputStream PrintWriter StringWriter]))

;;; =========================================================
;;; [A02] Cryptographic Failures – Hardcoded Secrets
;;; =========================================================

(def db-spec
  {:subprotocol "mysql"
   :subname     "//localhost:3306/mydb"
   :user        "root"
   :password    "P@ssw0rd123"})          ; [VULN-C-A02-1] Hardcoded DB password

(def ^:private secret-key "MySuperSecretKey12345") ; [VULN-C-A02-2] Hardcoded AES key
(def ^:private api-key    "sk-abcdef1234567890")   ; [VULN-C-A02-3] Hardcoded API key
(def ^:private admin-tok  "static-admin-token-xyz"); [VULN-C-A07-1] Hardcoded admin token

;; [A02] Weak password hashing – MD5, no salt
(defn hash-password [password]
  ;; [VULN-C-A02-4] MD5 is cryptographically broken; no salt applied
  (let [md   (MessageDigest/getInstance "MD5")
        hash (.digest md (.getBytes password "UTF-8"))]
    (.encodeToString (Base64/getEncoder) hash)))

;; [A02] Weak symmetric encryption – DES + ECB mode
(defn encrypt-des [^String plaintext]
  ;; [VULN-C-A02-5] DES is 56-bit and brute-forceable
  ;; [VULN-C-A02-6] ECB mode reveals data patterns (penguin attack)
  (let [key-bytes (.getBytes (subs secret-key 0 8) "UTF-8")
        key-spec  (SecretKeySpec. key-bytes "DES")
        cipher    (doto (Cipher/getInstance "DES/ECB/PKCS5Padding")
                    (.init Cipher/ENCRYPT_MODE key-spec))]
    (.doFinal cipher (.getBytes plaintext "UTF-8"))))

;;; =========================================================
;;; [A03] Injection – SQL Injection
;;; =========================================================

(defn get-user-by-name [username]
  ;; [VULN-C-A03-1] SQL injection: username interpolated directly into query string
  (jdbc/query db-spec
    [(str "SELECT * FROM users WHERE username = '" username "'")]))

(defn search-products [category]
  ;; [VULN-C-A03-2] SQL injection via string concatenation
  (jdbc/execute! db-spec
    [(str "SELECT * FROM products WHERE category = '" category "'")]))

;; [A03] OS Command Injection
(defn run-ping [host]
  ;; [VULN-C-A03-3] Command injection: host passed unsanitized to shell
  (sh "bash" "-c" (str "ping -c 1 " host)))

;; [A03] Code Injection via eval / read-string
(defn evaluate-expression [user-expr]
  ;; [VULN-C-A03-4] Arbitrary Clojure code execution via eval + read-string
  (eval (read-string user-expr)))

;;; =========================================================
;;; [A01] Broken Access Control
;;; =========================================================

(defn get-user-profile [requesting-user-id target-user-id]
  ;; [VULN-C-A01-1] No check that requesting user owns or is admin for target-user-id
  (jdbc/query db-spec
    ["SELECT * FROM users WHERE id = ?" target-user-id]))

(defn delete-record [record-id]
  ;; [VULN-C-A01-2] No authorization check before deleting record
  (jdbc/execute! db-spec
    ["DELETE FROM records WHERE id = ?" record-id]))

(defn read-file [filename]
  ;; [VULN-C-A01-3] Path traversal: filename may contain "../../etc/passwd"
  (slurp (str "/var/app/uploads/" filename)))

(defn get-admin-report []
  ;; [VULN-C-A01-4] Endpoint has no authentication gate; returns sensitive data to any caller
  (jdbc/query db-spec ["SELECT * FROM admin_logs"]))

;;; =========================================================
;;; [A07] Identification and Authentication Failures
;;; =========================================================

(defn authenticate [username password]
  ;; [VULN-C-A07-2] Hardcoded backdoor credentials bypass real authentication
  (or (and (= username "admin") (= password "admin123"))
      ;; [VULN-C-A07-3] No account lockout or brute-force protection
      (seq (jdbc/query db-spec
             ["SELECT id FROM users WHERE username = ? AND password_md5 = ?"
              username (hash-password password)]))))

(defn generate-token [user-id]
  ;; [VULN-C-A07-4] Predictable, non-cryptographic session token
  (str "token-" user-id "-" (System/currentTimeMillis)))

(defn reset-password [email]
  ;; [VULN-C-A07-5] Password reset link sent with predictable token (timestamp only)
  (let [reset-token (str "reset-" (System/currentTimeMillis))]
    (println (str "Reset link: https://app.example.com/reset?token=" reset-token))))

;;; =========================================================
;;; [A08] Software and Data Integrity Failures – Insecure Deserialization
;;; =========================================================

(defn deserialize-object [^bytes data]
  ;; [VULN-C-A08-1] Java deserialization of untrusted bytes → potential RCE
  (with-open [ois (ObjectInputStream. (ByteArrayInputStream. data))]
    (.readObject ois)))

(defn load-config-yaml [yaml-str]
  ;; [VULN-C-A08-2] Unsafe SnakeYAML load with default constructor resolver
  ;; allows arbitrary Java class instantiation via YAML tags
  ;; (yaml/parse-string yaml-str)  ← do NOT call with untrusted input
  (println "Parsing YAML config (unsafe):" yaml-str))

(defn install-plugin [plugin-url]
  ;; [VULN-C-A08-3] Downloading and loading a JAR with no signature / checksum verification
  (let [local-path "/tmp/plugin.jar"]
    (:body (http/get plugin-url {:as :byte-array :output-coercion :bytes}))
    (println "Loading unverified plugin from" local-path)))

;;; =========================================================
;;; [A09] Security Logging and Monitoring Failures
;;; =========================================================

(defn log-login-attempt [username password success?]
  ;; [VULN-C-A09-1] Plaintext password written to stdout / log file
  (println (str "[LOG] username=" username " password=" password " success=" success?)))

(defn log-payment [card-number amount]
  ;; [VULN-C-A09-2] Full PAN logged – PCI DSS violation
  (println (str "[AUDIT] card=" card-number " amount=" amount)))

(defn log-api-call [endpoint params]
  ;; [VULN-C-A09-3] All request params (may include secrets/tokens) logged verbatim
  (println (str "[API] endpoint=" endpoint " params=" (pr-str params))))

;;; =========================================================
;;; [A10] Server-Side Request Forgery (SSRF)
;;; =========================================================

(defn fetch-url [user-url]
  ;; [VULN-C-A10-1] No URL allowlist; attacker can probe internal services
  ;; e.g., "http://169.254.169.254/latest/meta-data/" on AWS
  (:body (http/get user-url {:throw-exceptions false})))

(defn load-user-avatar [image-url]
  ;; [VULN-C-A10-2] SSRF via user-supplied image URL
  (:body (http/get image-url {:as :byte-array :throw-exceptions false})))

;;; =========================================================
;;; [A05] Security Misconfiguration
;;; =========================================================

(defn error-response [^Exception e]
  ;; [VULN-C-A05-1] Full exception + stack trace returned in HTTP response body
  (let [sw (StringWriter.)
        pw (PrintWriter. sw)]
    (.printStackTrace e pw)
    {:status  500
     :headers {"Content-Type" "text/plain"}
     :body    (str "Internal Error: " (.getMessage e) "\n" (.toString sw))}))

(def app-config
  {;; [VULN-C-A05-2] Debug mode enabled exposes internal routes and error details
   :debug         true
   ;; [VULN-C-A05-3] Wildcard CORS allows any origin to read responses
   :cors-origin   "*"
   ;; [VULN-C-A05-4] Session cookie not flagged Secure – sent over HTTP
   :cookie-secure false
   ;; [VULN-C-A05-5] HttpOnly not set – cookie accessible to JavaScript (XSS risk)
   :cookie-http-only false})

;;; =========================================================
;;; [A04] Insecure Design – Missing Business Logic Controls
;;; =========================================================

(defn transfer-funds [from-acc to-acc amount]
  ;; [VULN-C-A04-1] Negative amount not validated → reverse-transfer attack
  ;; [VULN-C-A04-2] No rate limiting → unlimited rapid transfers
  ;; [VULN-C-A04-3] No idempotency key → duplicate transactions on retry
  (jdbc/execute! db-spec ["UPDATE accounts SET balance = balance - ? WHERE id = ?" amount from-acc])
  (jdbc/execute! db-spec ["UPDATE accounts SET balance = balance + ? WHERE id = ?" amount to-acc]))

(defn apply-discount [user-id discount-pct]
  ;; [VULN-C-A04-4] No upper bound check; discount-pct of 200 gives free items + credit
  (jdbc/execute! db-spec
    ["UPDATE orders SET discount = ? WHERE user_id = ?" discount-pct user-id]))

;;; =========================================================
;;; [A06] Vulnerable and Outdated Components
;;; =========================================================

;; project.clj dependencies (illustrative – do NOT ship):
;;
;;   [org.clojure/clojure "1.8.0"]          ; [VULN-C-A06-1] EOL, multiple CVEs fixed in later releases
;;   [commons-collections "3.1"]            ; [VULN-C-A06-2] CVE-2015-4852: RCE gadget chain
;;   [ring/ring-core "1.6.0"]               ; [VULN-C-A06-3] Known session fixation issues fixed in 1.9+
;;   [cheshire "5.8.0"]                     ; [VULN-C-A06-4] Outdated JSON lib; use 5.12.0+

(defn get-component-versions []
  ;; [VULN-C-A06-5] No automated SCA / dependency vulnerability scanning in CI pipeline
  {:clojure           (clojure-version)
   :commons-collections "3.1"     ; vulnerable
   :ring-core           "1.6.0"}) ; vulnerable

(defn -main [& _args]
  (println "=== SAST Vulnerability Test – Clojure (OWASP Top 10 2021) ==="))
