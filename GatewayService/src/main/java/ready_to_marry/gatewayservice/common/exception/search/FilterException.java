package ready_to_marry.gatewayservice.common.exception.search;

import lombok.Getter;
import ready_to_marry.gatewayservice.common.exception.ErrorCode;

@Getter
public class FilterException extends RuntimeException {

    private final int code;

    public FilterException(ErrorCode errorCode) {
        super(errorCode.getMessage());
        this.code = errorCode.getCode();
    }
}