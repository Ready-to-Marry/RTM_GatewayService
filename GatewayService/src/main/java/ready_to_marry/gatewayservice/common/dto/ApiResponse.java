package ready_to_marry.gatewayservice.common.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ApiResponse<T> {
    private int code; // 0: 정상, 1 이상: 비즈니스 오류 코드
    private String message; // 메시지
    private T data; // 응답 데이터

    // 리스트 조회 시 페이징 정보, null 시 JSON에서 제외
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private Meta meta;

    // 검증 오류 발생 시 필드별 상세 메시지, 빈 리스트 또는 null 시 JSON에서 제외
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private List<ErrorDetail> errors;
}