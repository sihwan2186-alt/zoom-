package com.zoom.security.authentication;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * 인증 보안 모듈 - MFA, HMAC 서명 토큰 기반 인증
 * Zoom 취약점 보완: 회의 참여자 검증 강화
 */
public class AuthModule {

    private static final int TOTP_LENGTH = 6;
    private static final long TOTP_VALID_PERIOD_MILLIS = TimeUnit.SECONDS.toMillis(30);
    private static final long TOKEN_VALID_PERIOD_MILLIS = TimeUnit.MINUTES.toMillis(30);
    private static final int PBKDF2_ITERATIONS = 210_000;
    private static final int PASSWORD_HASH_BYTES = 32;
    private static final int MAX_FAILED_PASSWORD_ATTEMPTS = 5;
    private static final long PASSWORD_LOCKOUT_MILLIS = TimeUnit.MINUTES.toMillis(5);

    private final SecureRandom secureRandom = new SecureRandom();
    private final Map<String, UserRecord> users = new ConcurrentHashMap<>();
    private final Map<String, MfaChallenge> mfaChallenges = new ConcurrentHashMap<>();
    private final Map<String, UserSession> sessions = new ConcurrentHashMap<>();
    private final Map<String, LoginAttempt> loginAttempts = new ConcurrentHashMap<>();
    private final byte[] tokenSigningKey = randomBytes(32);

    static class UserRecord {
        String userId;
        String username;
        byte[] passwordSalt;
        byte[] passwordHash;

        UserRecord(String userId, String username, byte[] passwordSalt, byte[] passwordHash) {
            this.userId = userId;
            this.username = username;
            this.passwordSalt = passwordSalt;
            this.passwordHash = passwordHash;
        }
    }

    static class MfaChallenge {
        String code;
        long expiresAt;
        boolean consumed;

        MfaChallenge(String code, long expiresAt) {
            this.code = code;
            this.expiresAt = expiresAt;
            this.consumed = false;
        }
    }

    static class LoginAttempt {
        int failedAttempts;
        long lockedUntil;
    }

    static class UserSession {
        String userId;
        String username;
        long createdAt;
        long lastAccessAt;
        boolean mfaVerified;

        UserSession(String userId, String username, boolean mfaVerified) {
            this.userId = userId;
            this.username = username;
            this.createdAt = System.currentTimeMillis();
            this.lastAccessAt = System.currentTimeMillis();
            this.mfaVerified = mfaVerified;
        }
    }

    public String registerUser(String username, String password) {
        if (username == null || username.trim().length() < 2 || password == null || password.length() < 8) {
            throw new IllegalArgumentException("username or password policy violation");
        }
        String normalizedUsername = username.trim();
        boolean duplicateUsername = users.values().stream()
            .anyMatch(user -> user.username.equalsIgnoreCase(normalizedUsername));
        if (duplicateUsername) {
            throw new IllegalArgumentException("duplicate username");
        }
        String userId = generateUserId();
        byte[] salt = randomBytes(16);
        byte[] hash = hashPassword(password, salt);
        users.put(userId, new UserRecord(userId, normalizedUsername, salt, hash));
        System.out.println("사용자 등록: " + normalizedUsername + " (ID: " + userId + ")");
        return userId;
    }

    public boolean verifyPassword(String userId, String password) {
        UserRecord user = users.get(userId);
        if (user == null || password == null) {
            return false;
        }
        if (isPasswordLocked(userId)) {
            return false;
        }
        byte[] inputHash = hashPassword(password, user.passwordSalt);
        boolean matched = MessageDigest.isEqual(user.passwordHash, inputHash);
        if (matched) {
            clearPasswordFailures(userId);
        } else {
            recordPasswordFailure(userId);
        }
        return matched;
    }

    public String generateTOTPCode(String userId) {
        if (!users.containsKey(userId)) {
            throw new IllegalArgumentException("unknown user");
        }
        int codeNumber = 100000 + secureRandom.nextInt(900000);
        String code = String.format("%0" + TOTP_LENGTH + "d", codeNumber);
        mfaChallenges.put(userId, new MfaChallenge(
            code,
            System.currentTimeMillis() + TOTP_VALID_PERIOD_MILLIS
        ));
        return code;
    }

    public boolean verifyTOTPCode(String userId, String inputCode) {
        MfaChallenge challenge = mfaChallenges.get(userId);
        if (challenge == null || challenge.consumed || inputCode == null) {
            return false;
        }
        if (System.currentTimeMillis() > challenge.expiresAt) {
            mfaChallenges.remove(userId);
            return false;
        }
        boolean matched = MessageDigest.isEqual(
            challenge.code.getBytes(StandardCharsets.UTF_8),
            inputCode.getBytes(StandardCharsets.UTF_8)
        );
        if (matched) {
            challenge.consumed = true;
        }
        return matched;
    }

    public String generateToken(String userId, String username, boolean mfaVerified) {
        UserRecord user = users.get(userId);
        if (user == null) {
            throw new IllegalArgumentException("unknown user");
        }
        if (!mfaVerified) {
            throw new IllegalStateException("MFA verification is required before token issuance");
        }
        String tokenId = generateSecureToken();
        long expiry = System.currentTimeMillis() + TOKEN_VALID_PERIOD_MILLIS;
        String body = tokenId + "." + expiry + "." + userId;
        String signature = sign(body);

        sessions.put(tokenId, new UserSession(userId, user.username, true));
        System.out.println("토큰 생성: " + safePrefix(tokenId) + "...");

        return body + "." + signature;
    }

    public boolean validateToken(String token) {
        if (token == null) {
            return false;
        }
        String[] parts = token.split("\\.");
        if (parts.length != 4) {
            return false;
        }

        String tokenId = parts[0];
        long expiry;
        try {
            expiry = Long.parseLong(parts[1]);
        } catch (NumberFormatException ex) {
            return false;
        }

        String body = parts[0] + "." + parts[1] + "." + parts[2];
        if (!MessageDigest.isEqual(sign(body).getBytes(StandardCharsets.UTF_8), parts[3].getBytes(StandardCharsets.UTF_8))) {
            return false;
        }

        if (System.currentTimeMillis() > expiry) {
            sessions.remove(tokenId);
            return false;
        }

        UserSession session = sessions.get(tokenId);
        if (session == null) {
            return false;
        }
        session.lastAccessAt = System.currentTimeMillis();
        return true;
    }

    public void invalidateToken(String token) {
        if (token == null) {
            return;
        }
        String[] parts = token.split("\\.");
        if (parts.length >= 1) {
            sessions.remove(parts[0]);
            System.out.println("세션 폐기: " + safePrefix(parts[0]) + "...");
        }
    }

    private String generateUserId() {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes(16));
    }

    private String generateSecureToken() {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes(32));
    }

    private byte[] randomBytes(int size) {
        byte[] bytes = new byte[size];
        secureRandom.nextBytes(bytes);
        return bytes;
    }

    private byte[] hashPassword(String password, byte[] salt) {
        PBEKeySpec spec = new PBEKeySpec(
            password.toCharArray(),
            salt,
            PBKDF2_ITERATIONS,
            PASSWORD_HASH_BYTES * 8
        );
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return factory.generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("password hashing failed", ex);
        } finally {
            spec.clearPassword();
        }
    }

    public boolean isPasswordLocked(String userId) {
        LoginAttempt attempt = loginAttempts.get(userId);
        if (attempt == null) {
            return false;
        }
        if (System.currentTimeMillis() > attempt.lockedUntil) {
            if (attempt.lockedUntil > 0) {
                loginAttempts.remove(userId);
            }
            return false;
        }
        return true;
    }

    private void recordPasswordFailure(String userId) {
        LoginAttempt attempt = loginAttempts.computeIfAbsent(userId, ignored -> new LoginAttempt());
        attempt.failedAttempts += 1;
        if (attempt.failedAttempts >= MAX_FAILED_PASSWORD_ATTEMPTS) {
            attempt.lockedUntil = System.currentTimeMillis() + PASSWORD_LOCKOUT_MILLIS;
        }
    }

    private void clearPasswordFailures(String userId) {
        loginAttempts.remove(userId);
    }

    private String sign(String body) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(tokenSigningKey, "HmacSHA256"));
            byte[] signature = mac.doFinal(body.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(signature);
        } catch (Exception ex) {
            throw new IllegalStateException("token signing failed", ex);
        }
    }

    private String safePrefix(String value) {
        return value.substring(0, Math.min(16, value.length()));
    }

    public static void main(String[] args) {
        AuthModule auth = new AuthModule();

        String userId = auth.registerUser("testuser", "password123");
        boolean passwordOk = auth.verifyPassword(userId, "password123");
        System.out.println("비밀번호 검증 결과: " + (passwordOk ? "성공" : "실패"));

        String totpCode = auth.generateTOTPCode(userId);
        System.out.println("MFA 코드: " + totpCode);

        boolean mfaResult = auth.verifyTOTPCode(userId, totpCode);
        System.out.println("MFA 검증 결과: " + (mfaResult ? "성공" : "실패"));

        String token = auth.generateToken(userId, "testuser", mfaResult);
        System.out.println("생성된 토큰: " + token.substring(0, 30) + "...");

        boolean valid = auth.validateToken(token);
        System.out.println("토큰 검증 결과: " + (valid ? "유효" : "무효"));

        auth.invalidateToken(token);
        System.out.println("폐기 후 토큰 검증 결과: " + (auth.validateToken(token) ? "유효" : "무효"));
    }
}
