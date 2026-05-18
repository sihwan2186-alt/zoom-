package com.videoconference.security.authentication;

import java.nio.ByteBuffer;
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
 * 화상회의 보안 보완: 회의 참여자 검증 강화
 */
public class AuthModule {

    private static final int TOTP_LENGTH = 6;
    private static final long TOTP_PERIOD_SECONDS = 30;
    private static final int TOTP_WINDOW_STEPS = 1;
    private static final long TOKEN_VALID_PERIOD_MILLIS = TimeUnit.MINUTES.toMillis(30);
    private static final int PBKDF2_ITERATIONS = 210_000;
    private static final int PASSWORD_HASH_BYTES = 32;
    private static final int MAX_FAILED_PASSWORD_ATTEMPTS = 5;
    private static final long PASSWORD_LOCKOUT_MILLIS = TimeUnit.MINUTES.toMillis(5);
    private static final int MAX_FAILED_MFA_ATTEMPTS = 5;
    private static final long MFA_LOCKOUT_MILLIS = TimeUnit.MINUTES.toMillis(5);

    private final SecureRandom secureRandom = new SecureRandom();
    private final Map<String, UserRecord> users = new ConcurrentHashMap<>();
    private final Map<String, UserSession> sessions = new ConcurrentHashMap<>();
    private final Map<String, LoginAttempt> loginAttempts = new ConcurrentHashMap<>();
    private final Map<String, LoginAttempt> mfaAttempts = new ConcurrentHashMap<>();
    private final Map<String, Long> revokedTokens = new ConcurrentHashMap<>();
    private final byte[] tokenSigningKey = randomBytes(32);

    static class UserRecord {
        String userId;
        String username;
        byte[] passwordSalt;
        byte[] passwordHash;
        byte[] mfaSecret;
        long lastTotpStep = -1;

        UserRecord(String userId, String username, byte[] passwordSalt, byte[] passwordHash, byte[] mfaSecret) {
            this.userId = userId;
            this.username = username;
            this.passwordSalt = passwordSalt;
            this.passwordHash = passwordHash;
            this.mfaSecret = mfaSecret;
        }
    }

    static class LoginAttempt {
        int failedAttempts;
        long lockedUntil;
    }

    static class UserSession {
        String userId;
        String username;
        String meetingId;
        String role;
        long createdAt;
        long lastAccessAt;
        boolean mfaVerified;

        UserSession(String userId, String username, String meetingId, String role, boolean mfaVerified) {
            this.userId = userId;
            this.username = username;
            this.meetingId = meetingId;
            this.role = role;
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
        byte[] mfaSecret = randomBytes(20);
        users.put(userId, new UserRecord(userId, normalizedUsername, salt, hash, mfaSecret));
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
        UserRecord user = users.get(userId);
        if (user == null) {
            throw new IllegalArgumentException("unknown user");
        }
        return generateTotpForStep(user.mfaSecret, currentTotpStep());
    }

    public boolean verifyTOTPCode(String userId, String inputCode) {
        UserRecord user = users.get(userId);
        if (user == null || inputCode == null || !inputCode.matches("\\d{" + TOTP_LENGTH + "}")) {
            return false;
        }
        if (isMfaLocked(userId)) {
            return false;
        }

        long currentStep = currentTotpStep();
        synchronized (user) {
            for (int offset = -TOTP_WINDOW_STEPS; offset <= TOTP_WINDOW_STEPS; offset++) {
                long candidateStep = currentStep + offset;
                if (candidateStep <= user.lastTotpStep) {
                    continue;
                }
                String expected = generateTotpForStep(user.mfaSecret, candidateStep);
                boolean matched = MessageDigest.isEqual(
                    expected.getBytes(StandardCharsets.UTF_8),
                    inputCode.getBytes(StandardCharsets.UTF_8)
                );
                if (matched) {
                    user.lastTotpStep = candidateStep;
                    clearMfaFailures(userId);
                    return true;
                }
            }
        }
        recordMfaFailure(userId);
        return false;
    }

    public String generateToken(String userId, String username, boolean mfaVerified) {
        return generateToken(userId, username, "default-room", "participant", mfaVerified);
    }

    public String generateToken(
        String userId,
        String username,
        String meetingId,
        String role,
        boolean mfaVerified
    ) {
        UserRecord user = users.get(userId);
        if (user == null) {
            throw new IllegalArgumentException("unknown user");
        }
        if (!mfaVerified) {
            throw new IllegalStateException("MFA verification is required before token issuance");
        }
        String normalizedMeetingId = normalizeTokenClaim(meetingId, "default-room");
        String normalizedRole = normalizeTokenClaim(role, "participant");
        String tokenId = generateSecureToken();
        long expiry = System.currentTimeMillis() + TOKEN_VALID_PERIOD_MILLIS;
        String body = tokenId + "." + expiry + "." + userId + "." + normalizedMeetingId + "." + normalizedRole;
        String signature = sign(body);

        sessions.put(tokenId, new UserSession(userId, user.username, normalizedMeetingId, normalizedRole, true));
        System.out.println("토큰 생성: " + safePrefix(tokenId) + "...");

        return body + "." + signature;
    }

    public boolean validateToken(String token) {
        if (token == null) {
            return false;
        }
        String[] parts = token.split("\\.");
        if (parts.length != 6) {
            return false;
        }

        String tokenId = parts[0];
        long expiry;
        try {
            expiry = Long.parseLong(parts[1]);
        } catch (NumberFormatException ex) {
            return false;
        }

        if (revokedTokens.containsKey(tokenId)) {
            return false;
        }

        String body = parts[0] + "." + parts[1] + "." + parts[2] + "." + parts[3] + "." + parts[4];
        if (!MessageDigest.isEqual(sign(body).getBytes(StandardCharsets.UTF_8), parts[5].getBytes(StandardCharsets.UTF_8))) {
            return false;
        }

        if (System.currentTimeMillis() > expiry) {
            sessions.remove(tokenId);
            revokedTokens.remove(tokenId);
            return false;
        }

        UserSession session = sessions.get(tokenId);
        if (session == null) {
            return false;
        }
        if (!session.userId.equals(parts[2]) || !session.meetingId.equals(parts[3]) || !session.role.equals(parts[4])) {
            return false;
        }
        session.lastAccessAt = System.currentTimeMillis();
        return true;
    }

    public boolean validateTokenForMeeting(String token, String expectedMeetingId) {
        if (!validateToken(token)) {
            return false;
        }
        String[] parts = token.split("\\.");
        return parts.length == 6 && MessageDigest.isEqual(
            normalizeTokenClaim(expectedMeetingId, "default-room").getBytes(StandardCharsets.UTF_8),
            parts[3].getBytes(StandardCharsets.UTF_8)
        );
    }

    public void invalidateToken(String token) {
        if (token == null) {
            return;
        }
        String[] parts = token.split("\\.");
        if (parts.length >= 1) {
            sessions.remove(parts[0]);
            if (parts.length >= 2) {
                try {
                    revokedTokens.put(parts[0], Long.parseLong(parts[1]));
                    cleanupRevokedTokens();
                } catch (NumberFormatException ignored) {
                    revokedTokens.put(parts[0], System.currentTimeMillis() + TOKEN_VALID_PERIOD_MILLIS);
                }
            }
            System.out.println("세션 폐기: " + safePrefix(parts[0]) + "...");
        }
    }

    private String generateUserId() {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes(16));
    }

    private String generateSecureToken() {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes(32));
    }

    private long currentTotpStep() {
        return TimeUnit.MILLISECONDS.toSeconds(System.currentTimeMillis()) / TOTP_PERIOD_SECONDS;
    }

    private String generateTotpForStep(byte[] secret, long step) {
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(secret, "HmacSHA1"));
            byte[] hash = mac.doFinal(ByteBuffer.allocate(8).putLong(step).array());
            int offset = hash[hash.length - 1] & 0x0f;
            int binary =
                ((hash[offset] & 0x7f) << 24)
                | ((hash[offset + 1] & 0xff) << 16)
                | ((hash[offset + 2] & 0xff) << 8)
                | (hash[offset + 3] & 0xff);
            int otp = binary % 1_000_000;
            return String.format("%0" + TOTP_LENGTH + "d", otp);
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("TOTP generation failed", ex);
        }
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

    public boolean isMfaLocked(String userId) {
        LoginAttempt attempt = mfaAttempts.get(userId);
        if (attempt == null) {
            return false;
        }
        if (System.currentTimeMillis() > attempt.lockedUntil) {
            if (attempt.lockedUntil > 0) {
                mfaAttempts.remove(userId);
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

    private void recordMfaFailure(String userId) {
        LoginAttempt attempt = mfaAttempts.computeIfAbsent(userId, ignored -> new LoginAttempt());
        attempt.failedAttempts += 1;
        if (attempt.failedAttempts >= MAX_FAILED_MFA_ATTEMPTS) {
            attempt.lockedUntil = System.currentTimeMillis() + MFA_LOCKOUT_MILLIS;
        }
    }

    private void clearMfaFailures(String userId) {
        mfaAttempts.remove(userId);
    }

    private void cleanupRevokedTokens() {
        long now = System.currentTimeMillis();
        revokedTokens.entrySet().removeIf(entry -> entry.getValue() < now);
    }

    private String normalizeTokenClaim(String value, String fallback) {
        String normalized = value == null || value.trim().isEmpty() ? fallback : value.trim();
        if (!normalized.matches("[A-Za-z0-9_-]{1,64}")) {
            throw new IllegalArgumentException("token claim contains unsupported characters");
        }
        return normalized;
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

        String token = auth.generateToken(userId, "testuser", "secure-room", "host", mfaResult);
        System.out.println("생성된 토큰: " + token.substring(0, 30) + "...");

        boolean valid = auth.validateToken(token);
        System.out.println("토큰 검증 결과: " + (valid ? "유효" : "무효"));
        System.out.println("회의방 바인딩 검증: " + (auth.validateTokenForMeeting(token, "secure-room") ? "유효" : "무효"));

        auth.invalidateToken(token);
        System.out.println("폐기 후 토큰 검증 결과: " + (auth.validateToken(token) ? "유효" : "무효"));
    }
}
