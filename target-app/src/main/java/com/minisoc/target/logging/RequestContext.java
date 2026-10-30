package com.minisoc.target.logging;

/** Keys shared between filters, MDC and request attributes. */
public final class RequestContext {

    public static final String CORRELATION_HEADER = "X-Correlation-ID";
    public static final String MDC_CORRELATION_ID = "correlation_id";
    public static final String MDC_SOURCE_IP = "source_ip";
    public static final String MDC_USERNAME = "username";
    /** JWT id (jti) of the presented token - lets detections spot one token used from many IPs. */
    public static final String MDC_TOKEN_ID = "token_id";
    /** Request attribute holding the authenticated username (survives SecurityContext clearing). */
    public static final String ATTR_USERNAME = "minisoc.username";

    private RequestContext() {
    }
}
