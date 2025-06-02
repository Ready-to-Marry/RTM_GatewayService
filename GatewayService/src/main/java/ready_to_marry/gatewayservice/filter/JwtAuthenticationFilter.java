package ready_to_marry.gatewayservice.filter;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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
import ready_to_marry.gatewayservice.config.JwtProperties;
import ready_to_marry.gatewayservice.util.JwtUtil;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

    private final JwtProperties jwtProperties;
    private final JwtUtil jwtUtil;

    //Mono -> Spring WebFlux가 제공하는 0개 또는 1개의 데이터 비동기 리턴 퍼블리셔
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        ServerHttpRequest request = exchange.getRequest();
        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        String path = request.getURI().getPath();

        if (isSkipPath(path)) {
            return chain.filter(exchange);
        }

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
            ServerHttpRequest.Builder mutatedRequestBuilder = request.mutate();

            switch (claims.getRole()) {
                case "ADMIN":
                    mutatedRequestBuilder
                            .header("X-Account-Id", claims.getAccountId())
                            .header("X-Admin-Id", String.valueOf(claims.getAccountId()))
                            .header("X-Admin-Role", claims.getAdminRole())
                            .header("X-Role", claims.getAdminRole());
                    System.out.println(claims.getAdminRole());
                    System.out.println("admin id"+String.valueOf(claims.getAccountId()));
                    System.out.println(claims.getAccountId());
                    System.out.println(claims.getAdminRole());
                    break;
                case "PARTNER":
                    mutatedRequestBuilder
                            .header("X-Account-Id", claims.getAccountId())
                            .header("X-Partner-Id", String.valueOf(claims.getPartnerId()))
                            .header("X-Role", claims.getRole());
                    System.out.println(claims.getRole());
                    System.out.println(claims.getPartnerId());
                    break;
                case "USER":
                default:
                    mutatedRequestBuilder
                            .header("X-Account-Id", claims.getAccountId())
                            .header("X-User-Id", String.valueOf(claims.getUserId()))
                            .header("X-Role", claims.getRole());
                    System.out.println(claims.getRole());
                    System.out.println(claims.getUserId());
                    break;
            }

            ServerHttpRequest mutatedRequest = mutatedRequestBuilder.build();
            log.info("Headers set: {}", mutatedRequest.getHeaders());
            return chain.filter(exchange.mutate().request(mutatedRequest).build());

        } catch (ExpiredJwtException e) {
            return Mono.error(new FilterException(ErrorCode.TOKEN_EXPIRED));
        } catch (SecurityException | SignatureException e) {
            return Mono.error(new FilterException(ErrorCode.TOKEN_SIGUNATURE));
        } catch (MalformedJwtException e) {
            return Mono.error(new FilterException(ErrorCode.MALFORMED_TOKEN));
        } catch (Exception e) {
            log.error("[JwtAuthenticationFilter] Unknown auth error occurred: {}", e.getMessage(), e);
            return Mono.error(new FilterException(ErrorCode.UNKNOWN_AUTH_ERROR));
        }
    }

    // 필터 우선순위
    @Override
    public int getOrder() {
        return -1;
    }

    private boolean isSkipPath(String path) {
        return jwtProperties.getSkipPaths().stream()
                .anyMatch(path::contains);
    }
}
