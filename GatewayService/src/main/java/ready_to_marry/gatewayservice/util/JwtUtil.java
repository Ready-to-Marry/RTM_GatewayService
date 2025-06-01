package ready_to_marry.gatewayservice.util;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import ready_to_marry.gatewayservice.common.dto.JwtClaims;
import ready_to_marry.gatewayservice.config.JwtProperties;

import java.security.Key;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtUtil {

    private final JwtProperties props;
    private Key key;

    @PostConstruct
    public void init() {
        // Base64 디코딩 후 HMAC-SHA256 키 생성
        byte[] secretBytes = Decoders.BASE64.decode(props.getSecretKey());
        this.key = Keys.hmacShaKeyFor(secretBytes);
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parser().setSigningKey(key).build().parseSignedClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            log.warn("[JwtUtil] Token validation failed: {}", e.getMessage(), e);
            return false;
        }
    }

    public JwtClaims getClaims(String token) {
        Claims claims = Jwts.parser().setSigningKey(key).build().parseSignedClaims(token).getPayload();

        return JwtClaims.builder()
                .role(claims.get("role", String.class))
                .userId(claims.get("userId", Long.class))
                .partnerId(claims.get("partnerId", Long.class))
                .adminRole(claims.get("adminRole", String.class))
                .accountId(claims.getSubject())
                .build();
    }
}

