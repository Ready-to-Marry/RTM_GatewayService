package ready_to_marry.gatewayservice.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;
import ready_to_marry.gatewayservice.common.dto.JwtClaims;

import java.security.Key;

@Component
public class JwtUtil {

    private final String secret = "WlwWlwWlwWlwWlwWlwWlwWlwWlwWlwWlwWlwWlwWlwWlwWlw";
    private final Key key = Keys.hmacShaKeyFor(secret.getBytes());

    // 토큰 유효성 검증
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    // JwtClaims 객체로 파싱
    public JwtClaims getClaims(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();

        return JwtClaims.builder()
                .role(claims.get("role", String.class))
                .userId(claims.get("userId", Long.class))
                .partnerId(claims.get("partnerId", Long.class))
                .adminRole(claims.get("adminRole", String.class))
                .build();
    }
}
