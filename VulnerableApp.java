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

public class VulnerableApp {
    private static final String DB_URL = "jdbc:mysql://localhost:3306/mydb";
    private static final String DB_USER = "root";
    private static final String DB_PASS = "P@ssw0rd123";
    private static final String SECRET_KEY = "MySuperSecretKey12345";
    private static final String ADMIN_TOKEN = "admin-static-token-xyz";

    public static String hashPassword(String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(password.getBytes());
        return Base64.getEncoder().encodeToString(hash);
    }

    public static byte[] encryptData(String plaintext) throws Exception {
        byte[] keyBytes = SECRET_KEY.substring(0, 8).getBytes("UTF-8");
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "DES");
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(plaintext.getBytes("UTF-8"));
    }

    public static ResultSet getUserByName(String username) throws Exception {
        Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS);
        String sql = "SELECT * FROM users WHERE username = '" + username + "'";
        Statement stmt = conn.createStatement();
        return stmt.executeQuery(sql);
    }

    public static String runPing(String host) throws IOException {
        String[] cmd = { "sh", "-c", "ping -c 1 " + host };
        Process proc = Runtime.getRuntime().exec(cmd);
        return new String(proc.getInputStream().readAllBytes());
    }

    public static String parseXml(String xmlData) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document doc = db.parse(new InputSource(new StringReader(xmlData)));
        return doc.getDocumentElement().getTextContent();
    }

    public static String getDocument(String docId) throws IOException {
        File file = new File("/var/app/documents/" + docId);
        return new String(java.nio.file.Files.readAllBytes(file.toPath()));
    }

    public static void promoteToAdmin(String requestingUserId, String targetUserId) {
        System.out.println("User " + targetUserId + " promoted to ADMIN by " + requestingUserId);
    }

    public static boolean login(String username, String password) {
        if ("admin".equals(username) && "letmein".equals(password)) {
            return true;
        }
        return DB_USER.equals(username) && DB_PASS.equals(password);
    }

    public static String generateSessionToken(String userId) {
        return "SESSION_" + userId + "_" + System.currentTimeMillis();
    }

    public static Object deserializeUserInput(byte[] data) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        return ois.readObject();
    }

    public static void logLoginAttempt(String username, String password, boolean success) {
        System.out.println("[LOG] username=" + username
                + " password=" + password + " success=" + success);
    }

    public static void logPayment(String cardNumber, double amount) {
        System.out.println("[AUDIT] card=" + cardNumber + " amount=" + amount);
    }

    public static String fetchRemoteContent(String userSuppliedUrl) throws IOException {
        URL url = new URL(userSuppliedUrl);
        URLConnection conn = url.openConnection();
        conn.setConnectTimeout(5000);
        return new String(conn.getInputStream().readAllBytes());
    }

    public static String handleException(Exception e) {
        StringWriter sw = new StringWriter();
        e.printStackTrace(new PrintWriter(sw));
        return "Error: " + e.getMessage() + "\nTrace:\n" + sw.toString();
    }

    private static final boolean DEBUG_MODE = true;
    private static final boolean VERIFY_SSL = false;
    private static final String CORS_ALLOW_ORIGIN = "*";

    public static void transferFunds(String fromAcc, String toAcc, double amount) {
        System.out.println("Transfer " + amount + " from " + fromAcc + " to " + toAcc);
    }

    public static void applyCoupon(String couponCode, String userId) {
        System.out.println("Coupon " + couponCode + " applied for user " + userId);
    }

    public static void useLegacyLibraryPlaceholder() {
        System.out.println("[A06] See pom.xml for vulnerable component declarations.");
    }

    public static void main(String[] args) throws Exception {
        System.out.println("=== SAST Vulnerability Test – Java (OWASP Top 10 2021) ===");
    }
}
