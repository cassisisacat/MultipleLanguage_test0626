package com.sast.test;

import java.sql.*;
import java.security.*;
import java.io.*;
import java.net.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.*;
import javax.xml.parsers.*;
import org.xml.sax.InputSource;
import org.w3c.dom.*;

/**
 * SAST Test File – Java
 * Intentional OWASP Top 10 (2021) vulnerabilities for SAST tool evaluation.
 * !! DO NOT USE IN PRODUCTION !!
 */
public class VulnerableApp {

    // =========================================================
    // [A02] Cryptographic Failures – Hardcoded Secrets
    // =========================================================
    private static final String DB_URL      = "jdbc:mysql://localhost:3306/mydb";
    private static final String DB_USER     = "root";
    private static final String DB_PASS     = "P@ssw0rd123";           // [VULN-J-A02-1] Hardcoded DB password
    private static final String SECRET_KEY  = "MySuperSecretKey12345"; // [VULN-J-A02-2] Hardcoded AES key
    private static final String ADMIN_TOKEN = "admin-static-token-xyz";// [VULN-J-A07-1] Hardcoded admin token

    // =========================================================
    // [A02] Cryptographic Failures – Weak Password Hashing (MD5, no salt)
    // =========================================================
    public static String hashPassword(String password) throws NoSuchAlgorithmException {
        // [VULN-J-A02-3] MD5 is cryptographically broken; no salt applied
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(password.getBytes());
        return Base64.getEncoder().encodeToString(hash);
    }

    // [A02] Weak symmetric encryption – DES + ECB mode
    public static byte[] encryptData(String plaintext) throws Exception {
        // [VULN-J-A02-4] DES key length is only 56-bit; brute-forceable
        byte[] keyBytes = SECRET_KEY.substring(0, 8).getBytes("UTF-8");
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "DES");
        // [VULN-J-A02-5] ECB mode does not hide data patterns (penguin attack)
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(plaintext.getBytes("UTF-8"));
    }

    // =========================================================
    // [A03] Injection – SQL Injection
    // =========================================================
    public static ResultSet getUserByName(String username) throws Exception {
        Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS);
        // [VULN-J-A03-1] SQL injection: username directly concatenated into query
        String sql = "SELECT * FROM users WHERE username = '" + username + "'";
        Statement stmt = conn.createStatement();
        return stmt.executeQuery(sql);
    }

    // [A03] Injection – OS Command Injection
    public static String runPing(String host) throws IOException {
        // [VULN-J-A03-2] Command injection: host appended to shell command unsanitized
        String[] cmd = { "sh", "-c", "ping -c 1 " + host };
        Process proc = Runtime.getRuntime().exec(cmd);
        return new String(proc.getInputStream().readAllBytes());
    }

    // [A03] Injection – XXE (XML External Entity)
    public static String parseXml(String xmlData) throws Exception {
        // [VULN-J-A03-3] XXE: DocumentBuilderFactory not hardened against external entities
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // MISSING: dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        // MISSING: dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document doc = db.parse(new InputSource(new StringReader(xmlData)));
        return doc.getDocumentElement().getTextContent();
    }

    // =========================================================
    // [A01] Broken Access Control – Missing Authorization
    // =========================================================
    public static String getDocument(String docId) throws IOException {
        // [VULN-J-A01-1] No ownership or role check; any caller reads any document
        // [VULN-J-A01-2] Path traversal: docId may contain "../../etc/passwd"
        File file = new File("/var/app/documents/" + docId);
        return new String(java.nio.file.Files.readAllBytes(file.toPath()));
    }

    public static void promoteToAdmin(String requestingUserId, String targetUserId) {
        // [VULN-J-A01-3] No verification that requestingUserId holds admin role
        System.out.println("User " + targetUserId + " promoted to ADMIN by " + requestingUserId);
    }

    // =========================================================
    // [A07] Identification and Authentication Failures
    // =========================================================
    public static boolean login(String username, String password) {
        // [VULN-J-A07-2] Hardcoded backdoor credentials bypass real auth
        if ("admin".equals(username) && "letmein".equals(password)) {
            return true;
        }
        // [VULN-J-A07-3] No account lockout – brute-force unrestricted
        // [VULN-J-A07-4] Plain-text password comparison without proper hashing
        return DB_USER.equals(username) && DB_PASS.equals(password);
    }

    public static String generateSessionToken(String userId) {
        // [VULN-J-A07-5] Predictable token: sequential ID + millisecond timestamp
        return "SESSION_" + userId + "_" + System.currentTimeMillis();
    }

    // =========================================================
    // [A08] Software and Data Integrity Failures – Insecure Deserialization
    // =========================================================
    public static Object deserializeUserInput(byte[] data) throws Exception {
        // [VULN-J-A08-1] Deserializing untrusted data with no type allowlist → RCE
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        return ois.readObject();
    }

    // =========================================================
    // [A09] Security Logging and Monitoring Failures
    // =========================================================
    public static void logLoginAttempt(String username, String password, boolean success) {
        // [VULN-J-A09-1] Plaintext password written to log – credential exposure
        System.out.println("[LOG] username=" + username
                + " password=" + password + " success=" + success);
    }

    public static void logPayment(String cardNumber, double amount) {
        // [VULN-J-A09-2] Full PAN (card number) written to log – PCI DSS violation
        System.out.println("[AUDIT] card=" + cardNumber + " amount=" + amount);
    }

    // =========================================================
    // [A10] Server-Side Request Forgery (SSRF)
    // =========================================================
    public static String fetchRemoteContent(String userSuppliedUrl) throws IOException {
        // [VULN-J-A10-1] No URL allowlist; attacker can reach internal services
        // e.g., http://169.254.169.254/latest/meta-data/ (AWS metadata)
        URL url = new URL(userSuppliedUrl);
        URLConnection conn = url.openConnection();
        conn.setConnectTimeout(5000);
        return new String(conn.getInputStream().readAllBytes());
    }

    // =========================================================
    // [A05] Security Misconfiguration
    // =========================================================
    public static String handleException(Exception e) {
        // [VULN-J-A05-1] Full stack trace returned to HTTP caller – internal disclosure
        StringWriter sw = new StringWriter();
        e.printStackTrace(new PrintWriter(sw));
        return "Error: " + e.getMessage() + "\nTrace:\n" + sw.toString();
    }

    // [A05] Insecure TLS / debug configuration (illustrative flags)
    private static final boolean DEBUG_MODE       = true;  // [VULN-J-A05-2] Debug enabled in prod
    private static final boolean VERIFY_SSL       = false; // [VULN-J-A05-3] TLS cert verification disabled
    private static final String  CORS_ALLOW_ORIGIN = "*";  // [VULN-J-A05-4] Wildcard CORS header

    // =========================================================
    // [A04] Insecure Design – Missing Business Logic Controls
    // =========================================================
    public static void transferFunds(String fromAcc, String toAcc, double amount) {
        // [VULN-J-A04-1] Negative amount not validated → reverse transfer attack
        // [VULN-J-A04-2] No rate limiting → unlimited rapid transfers
        // [VULN-J-A04-3] No idempotency key → duplicate transfers on retry
        System.out.println("Transfer " + amount + " from " + fromAcc + " to " + toAcc);
    }

    public static void applyCoupon(String couponCode, String userId) {
        // [VULN-J-A04-4] No check whether coupon already redeemed by this user
        System.out.println("Coupon " + couponCode + " applied for user " + userId);
    }

    // =========================================================
    // [A06] Vulnerable and Outdated Components
    // =========================================================
    //
    // Declared in pom.xml (do NOT ship):
    //
    //   <dependency>
    //     <groupId>commons-collections</groupId>
    //     <artifactId>commons-collections</artifactId>
    //     <version>3.1</version>
    //     <!-- [VULN-J-A06-1] CVE-2015-4852: RCE via Java deserialization gadget chain -->
    //   </dependency>
    //
    //   <dependency>
    //     <groupId>org.apache.struts</groupId>
    //     <artifactId>struts2-core</artifactId>
    //     <version>2.3.12</version>
    //     <!-- [VULN-J-A06-2] CVE-2017-5638: Remote Code Execution via Content-Type header -->
    //   </dependency>
    //
    //   <dependency>
    //     <groupId>log4j</groupId>
    //     <artifactId>log4j</artifactId>
    //     <version>1.2.17</version>
    //     <!-- [VULN-J-A06-3] CVE-2019-17571: Deserialization of untrusted data -->
    //   </dependency>
    public static void useLegacyLibraryPlaceholder() {
        System.out.println("[A06] See pom.xml for vulnerable component declarations.");
    }

    // =========================================================
    // Main
    // =========================================================
    public static void main(String[] args) throws Exception {
        System.out.println("=== SAST Vulnerability Test – Java (OWASP Top 10 2021) ===");
    }
}
