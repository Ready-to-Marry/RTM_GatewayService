package ready_to_marry.gatewayservice.common.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@AllArgsConstructor
@NoArgsConstructor
public class ErrorDetail {
    private String field; // 오류가 발생한 필드
    private String reason; // 오류 발생 이유
}