package ready_to_marry.gatewayservice.filter;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import lombok.RequiredArgsConstructor;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import ready_to_marry.gatewayservice.common.dto.JwtClaims;
import ready_to_marry.gatewayservice.common.exception.ErrorCode;
import ready_to_marry.gatewayservice.common.exception.search.FilterException;
import ready_to_marry.gatewayservice.util.JwtUtil;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    private final JwtUtil jwtUtil;

    //Mono -> Spring WebFlux가 제공하는 0개 또는 1개의 데이터 비동기 리턴 퍼블리셔
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        ServerHttpRequest request = exchange.getRequest();
        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        // Authorization 헤더 체크
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new FilterException(ErrorCode.TOKEN_HEADER_LESS);
        }

        String token = authHeader.substring(7);

        try {
            if (!jwtUtil.validateToken(token)) {
                throw new FilterException(ErrorCode.MALFORMED_TOKEN);
            }

            JwtClaims claims = jwtUtil.getClaims(token);
            String path = request.getURI().getPath();
            ServerHttpRequest.Builder mutatedRequestBuilder = request.mutate();

            switch (claims.getRole()) {
                case "ADMIN":
                    if (path.contains("/admin-service")) {
                        mutatedRequestBuilder
                                .header("X-Admin-Id", String.valueOf(claims.getUserId())) // userId 사용
                                .header("X-Admin-Role", claims.getAdminRole())
                                .header("X-Role", claims.getAdminRole());
                    }
                    break;
                case "PARTNER":
                    if (path.contains("/partner-service")) {
                        mutatedRequestBuilder
                                .header("X-Partner-Id", String.valueOf(claims.getPartnerId()))
                                .header("X-Role", claims.getRole());
                    }
                    break;
                case "USER":
                default:
                    mutatedRequestBuilder
                            .header("X-User-Id", String.valueOf(claims.getUserId()))
                            .header("X-Role", claims.getRole());
                    break;
            }

            ServerHttpRequest mutatedRequest = mutatedRequestBuilder.build();
            return chain.filter(exchange.mutate().request(mutatedRequest).build());

        } catch (ExpiredJwtException e) {
            return Mono.error(new FilterException(ErrorCode.TOKEN_EXPIRED));
        } catch (SecurityException | SignatureException e) {
            return Mono.error(new FilterException(ErrorCode.TOKEN_SIGUNATURE));
        } catch (MalformedJwtException e) {
            return Mono.error(new FilterException(ErrorCode.MALFORMED_TOKEN));
        } catch (Exception e) {
            return Mono.error(new FilterException(ErrorCode.UNKNOWN_AUTH_ERROR));
        }
    }

    // 필터 우선순위
    @Override
    public int getOrder() {
        return -1;
    }
}
