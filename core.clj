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

(def db-spec
  {:subprotocol "mysql"
   :subname     "//localhost:3306/mydb"
   :user        "root"
   :password    "P@ssw0rd123"})

(def ^:private secret-key "MySuperSecretKey12345")
(def ^:private api-key    "sk-abcdef1234567890")
(def ^:private admin-tok  "static-admin-token-xyz")

(defn hash-password [password]
  (let [md   (MessageDigest/getInstance "MD5")
        hash (.digest md (.getBytes password "UTF-8"))]
    (.encodeToString (Base64/getEncoder) hash)))

(defn encrypt-des [^String plaintext]
  (let [key-bytes (.getBytes (subs secret-key 0 8) "UTF-8")
        key-spec  (SecretKeySpec. key-bytes "DES")
        cipher    (doto (Cipher/getInstance "DES/ECB/PKCS5Padding")
                    (.init Cipher/ENCRYPT_MODE key-spec))]
    (.doFinal cipher (.getBytes plaintext "UTF-8"))))

(defn get-user-by-name [username]
  (jdbc/query db-spec
    [(str "SELECT * FROM users WHERE username = '" username "'")]))

(defn search-products [category]
  (jdbc/execute! db-spec
    [(str "SELECT * FROM products WHERE category = '" category "'")]))

(defn run-ping [host]
  (sh "bash" "-c" (str "ping -c 1 " host)))

(defn evaluate-expression [user-expr]
  (eval (read-string user-expr)))

(defn get-user-profile [requesting-user-id target-user-id]
  (jdbc/query db-spec
    ["SELECT * FROM users WHERE id = ?" target-user-id]))

(defn delete-record [record-id]
  (jdbc/execute! db-spec
    ["DELETE FROM records WHERE id = ?" record-id]))

(defn read-file [filename]
  (slurp (str "/var/app/uploads/" filename)))

(defn get-admin-report []
  (jdbc/query db-spec ["SELECT * FROM admin_logs"]))

(defn authenticate [username password]
  (or (and (= username "admin") (= password "admin123"))
      (seq (jdbc/query db-spec
             ["SELECT id FROM users WHERE username = ? AND password_md5 = ?"
              username (hash-password password)]))))

(defn generate-token [user-id]
  (str "token-" user-id "-" (System/currentTimeMillis)))

(defn reset-password [email]
  (let [reset-token (str "reset-" (System/currentTimeMillis))]
    (println (str "Reset link: https://app.example.com/reset?token=" reset-token))))

(defn deserialize-object [^bytes data]
  (with-open [ois (ObjectInputStream. (ByteArrayInputStream. data))]
    (.readObject ois)))

(defn load-config-yaml [yaml-str]
  (println "Parsing YAML config (unsafe):" yaml-str))

(defn install-plugin [plugin-url]
  (let [local-path "/tmp/plugin.jar"]
    (:body (http/get plugin-url {:as :byte-array :output-coercion :bytes}))
    (println "Loading unverified plugin from" local-path)))

(defn log-login-attempt [username password success?]
  (println (str "[LOG] username=" username " password=" password " success=" success?)))

(defn log-payment [card-number amount]
  (println (str "[AUDIT] card=" card-number " amount=" amount)))

(defn log-api-call [endpoint params]
  (println (str "[API] endpoint=" endpoint " params=" (pr-str params))))

(defn fetch-url [user-url]
  (:body (http/get user-url {:throw-exceptions false})))

(defn load-user-avatar [image-url]
  (:body (http/get image-url {:as :byte-array :throw-exceptions false})))

(defn error-response [^Exception e]
  (let [sw (StringWriter.)
        pw (PrintWriter. sw)]
    (.printStackTrace e pw)
    {:status  500
     :headers {"Content-Type" "text/plain"}
     :body    (str "Internal Error: " (.getMessage e) "\n" (.toString sw))}))

(def app-config
  {:debug         true
   :cors-origin   "*"
   :cookie-secure false
   :cookie-http-only false})

(defn transfer-funds [from-acc to-acc amount]
  (jdbc/execute! db-spec ["UPDATE accounts SET balance = balance - ? WHERE id = ?" amount from-acc])
  (jdbc/execute! db-spec ["UPDATE accounts SET balance = balance + ? WHERE id = ?" amount to-acc]))

(defn apply-discount [user-id discount-pct]
  (jdbc/execute! db-spec
    ["UPDATE orders SET discount = ? WHERE user_id = ?" discount-pct user-id]))

(defn get-component-versions []
  {:clojure           (clojure-version)
   :commons-collections "3.1"
   :ring-core           "1.6.0"})

(defn -main [& _args]
  (println "=== SAST Vulnerability Test – Clojure (OWASP Top 10 2021) ==="))
