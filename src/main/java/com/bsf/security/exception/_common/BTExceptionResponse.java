package com.bsf.security.exception._common;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import org.springframework.http.HttpStatus;
import java.time.LocalDateTime;

public class BTExceptionResponse {

    @Getter
    @JsonProperty("message")
    private final String message;

    @Getter
    @JsonProperty("status")
    private final int status;

    @Getter
    @JsonProperty("timestamp")
    private final LocalDateTime timestamp;

    public BTExceptionResponse(String message, HttpStatus httpStatus) {
        this.message = message;
        this.status = httpStatus.value();
        this.timestamp = LocalDateTime.now();
    }

}
