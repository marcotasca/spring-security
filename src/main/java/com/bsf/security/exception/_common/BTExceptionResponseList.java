package com.bsf.security.exception._common;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import org.springframework.http.HttpStatus;

import java.time.LocalDateTime;
import java.util.List;

public class BTExceptionResponseList {

    @Getter
    @JsonProperty("messages")
    private final List<String> messages;

    @Getter
    @JsonProperty("status")
    private final int status;

    @Getter
    @JsonProperty("timestamp")
    private final LocalDateTime timestamp;

    public BTExceptionResponseList(List<String> messages, HttpStatus httpStatus) {
        this.messages = messages;
        this.status = httpStatus.value();
        this.timestamp = LocalDateTime.now();
    }

}
