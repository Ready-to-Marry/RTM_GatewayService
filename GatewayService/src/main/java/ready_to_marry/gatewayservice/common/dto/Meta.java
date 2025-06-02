package ready_to_marry.gatewayservice.common.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@AllArgsConstructor
@NoArgsConstructor
public class Meta {
    private int page; // 현재 페이지
    private int size; // 페이지 크기
    private long totalElements; // 전체 아이템 수
    private int totalPages; // 전체 페이지 수
}