package ready_to_marry.gatewayservice.common.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import ready_to_marry.gatewayservice.common.dto.ApiResponse;
import ready_to_marry.gatewayservice.common.exception.search.FilterException;

@RestControllerAdvice
public class GlobalExceptionHandler {

    // SearchException을 처리하는 핸들러
    @ExceptionHandler(FilterException.class)
    public ResponseEntity<ApiResponse<Void>> handlePaymentException(FilterException ex) {
        ApiResponse<Void> body = ApiResponse.<Void>builder()
                .code(ex.getCode())
                .message(ex.getMessage())
                .data(null)
                .build();
        return ResponseEntity.status(HttpStatus.OK).body(body);
    }

    // 일반적인 예외를 처리하는 핸들러
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<Void>> handleGeneralException(Exception ex) {
        // 일반적인 예외의 경우
        ApiResponse<Void> body = ApiResponse.<Void>builder()
                .code(500)
                .message("Internal Server Error")
                .data(null)
                .build();
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(body);
    }
}