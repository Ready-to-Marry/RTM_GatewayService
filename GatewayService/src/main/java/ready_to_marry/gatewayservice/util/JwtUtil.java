package ready_to_marry.gatewayservice.util;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import ready_to_marry.gatewayservice.common.dto.JwtClaims;
import ready_to_marry.gatewayservice.config.JwtProperties;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.Key;

@Slf4j
@Component
public class JwtUtil {

    private final SecretKey key;

    public JwtUtil(JwtProperties jwtProperties) {
        // 0.12.3은 UTF-8 명시 필요
        this.key = Keys.hmacShaKeyFor(jwtProperties.getSecretKey().getBytes(StandardCharsets.UTF_8));
    }

    public boolean validateToken(String token) {
        try {
            // parser() → parserBuilder() 로 변경됨
            Jwts.parser().verifyWith(key).build().parseSignedClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            log.warn("[JwtUtil] Token validation failed: {}", e.getMessage(), e);
            return false;
        }
    }

    public JwtClaims getClaims(String token) {
        Claims claims = Jwts.parser().verifyWith(key).build().parseSignedClaims(token).getPayload();

        return JwtClaims.builder()
                .role(claims.get("role", String.class))
                .userId(claims.get("userId", Long.class))
                .partnerId(claims.get("partnerId", Long.class))
                .adminRole(claims.get("adminRole", String.class))
                .accountId(claims.getSubject())
                .build();
    }
}

