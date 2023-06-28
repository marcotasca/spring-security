package com.bsf.security.error;

import com.bsf.security.exception._common.BTExceptionResolver;
import com.bsf.security.exception._common.BTExceptionResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

@Slf4j
@RestControllerAdvice
@RequiredArgsConstructor
public class UnhandledErrorAdvice extends ResponseEntityExceptionHandler {

    private final BTExceptionResolver btExceptionResolver;

    @ExceptionHandler({Exception.class})
    public ResponseEntity<BTExceptionResponse> exception(Exception ex) {
        StackTraceElement[] stackTrace = ex.getStackTrace();
        if (stackTrace.length > 0) {
            StackTraceElement firstStackTraceElement = stackTrace[0];
            String className = firstStackTraceElement.getClassName();
            String methodName = firstStackTraceElement.getMethodName();
            int lineNumber = firstStackTraceElement.getLineNumber();
            String fileName = firstStackTraceElement.getFileName();

            log.info("{}::{}() [Lines: {}] - {}",
                    fileName == null ? null : fileName.replace(".java", ""),
                    methodName,
                    lineNumber,
                    ex.getMessage()
            );
            System.out.println("Eccezione generata dalla funzione: " + className + "." + methodName + "() alla riga " + lineNumber);
            System.out.println(fileName);
            System.out.println(firstStackTraceElement.getModuleName());
            System.out.println(firstStackTraceElement.getModuleVersion());
        }
        return new ResponseEntity<>(new BTExceptionResponse(ex.getMessage(), HttpStatus.BAD_REQUEST), HttpStatus.BAD_REQUEST);
    }

}
