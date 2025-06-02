package ready_to_marry.gatewayservice.common.exception;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum ErrorCode {

    // 1xxx: 비즈니스 오류
    TOKEN_EXPIRED(3001, "Access token expired"),
    TOKEN_SIGUNATURE(3002, "Invalid token signature"),
    MALFORMED_TOKEN(3003, "Malformed token"),
    TOKEN_HEADER_LESS(3004, "Access token header less"),
    UNKNOWN_AUTH_ERROR(3005, "Unknown auth error");

    private final int code;
    private final String message;
}