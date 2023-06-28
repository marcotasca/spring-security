package com.bsf.security.exception._common;

import lombok.Getter;
import org.springframework.http.HttpStatus;

import java.time.LocalDateTime;
import java.util.List;

public class BTException extends RuntimeException {

    @Getter
    private String message;

    @Getter
    private Object[] args;

    @Getter
    private HttpStatus status;

    @Getter
    private LocalDateTime timestamp;

    public BTException() {
        super();
    }

    public BTException(String message) {
        super();
        this.message = message;
    }

    public BTException(Object[] args) {
        super();
        this.args = args;
    }

    public BTException(String message, Object[] args) {
        super();
        this.message = message;
        this.args = args;
    }

    public BTException(String message, HttpStatus status, LocalDateTime timestamp) {
        super();
        this.message = message;
        this.status = status;
        this.timestamp = timestamp;
    }

}
