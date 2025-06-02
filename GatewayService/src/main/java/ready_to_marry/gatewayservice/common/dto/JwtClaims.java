package ready_to_marry.gatewayservice.common.dto;

import lombok.*;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class JwtClaims {
    // "USER", "PARTNER", "ADMIN"
    private String role;

    // 일반 유저(USER)일 때만 사용
    private Long userId;

    // 파트너(PARTNER)일 때만 사용
    private Long partnerId;

    // 관리자(ADMIN)일 때만 사용
    private String adminRole;

    private String accountId;
}

