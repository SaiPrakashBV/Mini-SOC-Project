package com.minisoc.target.web;

import com.minisoc.target.logging.RequestContext;
import org.slf4j.MDC;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Converts application errors to RFC 7807 problem details. AccessDeniedException is
 * deliberately not handled here so it reaches Spring Security's AccessDeniedHandler,
 * which records the audit event.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(NotFoundException.class)
    ProblemDetail notFound(NotFoundException e) {
        return problem(HttpStatus.NOT_FOUND, e.getMessage());
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    ProblemDetail invalid(MethodArgumentNotValidException e) {
        var pd = problem(HttpStatus.BAD_REQUEST, "Validation failed");
        pd.setProperty("errors", e.getBindingResult().getFieldErrors().stream()
                .map(f -> f.getField() + ": " + f.getDefaultMessage()).toList());
        return pd;
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    ProblemDetail unreadable() {
        return problem(HttpStatus.BAD_REQUEST, "Malformed request body");
    }

    private static ProblemDetail problem(HttpStatus status, String detail) {
        var pd = ProblemDetail.forStatusAndDetail(status, detail);
        pd.setProperty("correlationId", MDC.get(RequestContext.MDC_CORRELATION_ID));
        return pd;
    }
}
