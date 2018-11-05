package com.shudong.spring.security.oauth2.server.filter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingRequestWrapper;
import org.springframework.web.util.ContentCachingResponseWrapper;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;

@Slf4j
@Component
public class OncePerRequestLoggingFilter extends OncePerRequestFilter implements Ordered {
    // put filter at the end of all other filters to make sure we are processing after all others
    private static final int order = Ordered.HIGHEST_PRECEDENCE;
    private static final List<MediaType> VISIBLE_TYPES = Arrays.asList(
            MediaType.valueOf("text/*"),
            MediaType.APPLICATION_FORM_URLENCODED,
            MediaType.APPLICATION_JSON,
            MediaType.APPLICATION_XML,
            MediaType.valueOf("application/*+json"),
            MediaType.valueOf("application/*+xml"),
            MediaType.MULTIPART_FORM_DATA
    );

    @Override
    public int getOrder() {
        return order;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (isAsyncDispatch(request)) {
            filterChain.doFilter(request, response);
        } else {
            doFilterWrapped(wrapRequest(request), wrapResponse(response), filterChain);
        }
    }

    protected void doFilterWrapped(ContentCachingRequestWrapper request, ContentCachingResponseWrapper response, FilterChain filterChain) throws ServletException, IOException {
        try {
            beforeRequest(request, response);
            filterChain.doFilter(request, response);
        } finally {
            afterRequest(request, response);
            response.copyBodyToResponse();
        }
    }

    protected void beforeRequest(ContentCachingRequestWrapper request, ContentCachingResponseWrapper response) {
        if (log.isDebugEnabled()) {
            try {
                logRequestHeader(request, request.getRemoteAddr() + "|>");
            } catch (Throwable th) {
                log.error("Uncaught throwable at beforeRequest", th);
            }
        }
    }

    protected void afterRequest(ContentCachingRequestWrapper request, ContentCachingResponseWrapper response) {
        if (log.isDebugEnabled()) {
            try {
                logRequestBody(request, request.getRemoteAddr() + "|>");
                logResponseHeader(response, request.getRemoteAddr() + "|<");
                logResponseBody(response, request.getRemoteAddr() + "|<");
            } catch (Throwable th) {
                log.error("Uncaught throwable at afterRequest", th);
            }
        }
    }

    private static void logRequestHeader(ContentCachingRequestWrapper request, String prefix) {
        String queryString = request.getQueryString();
        if (queryString == null) {
            log.debug("{} {} {}", prefix, request.getMethod(), request.getRequestURI());
        } else {
            log.debug("{} {} {}?{}", prefix, request.getMethod(), request.getRequestURI(), queryString);
        }
        Collections.list(request.getHeaderNames()).forEach(headerName -> Collections.list(request.getHeaders(headerName)).forEach(headerValue -> log.debug("{} {}: {}", prefix, headerName, headerValue)));
        log.debug("{}", prefix);
    }

    private static void logRequestBody(ContentCachingRequestWrapper request, String prefix) {
        byte[] content = request.getContentAsByteArray();
        if (content.length > 0) {
            logContent(content, request.getContentType(), request.getCharacterEncoding(), prefix);
        }
    }

    private static void logResponseHeader(ContentCachingResponseWrapper response, String prefix) {
        int status = response.getStatus();
        log.debug("{} {} {}", prefix, status, HttpStatus.valueOf(status).getReasonPhrase());
        response.getHeaderNames().forEach(headerName -> response.getHeaders(headerName).forEach(headerValue -> log.debug("{} {}: {}", prefix, headerName, headerValue)));
        log.debug("{}", prefix);
    }

    private static void logResponseBody(ContentCachingResponseWrapper response, String prefix) {
        byte[] content = response.getContentAsByteArray();
        if (content.length > 0) {
            logContent(content, response.getContentType(), response.getCharacterEncoding(), prefix);
        }
    }

    private static void logContent(byte[] content, String contentType, String contentEncoding, String prefix) {
        MediaType mediaType = MediaType.valueOf(contentType);
        boolean visible = VISIBLE_TYPES.stream().anyMatch(visibleType -> visibleType.includes(mediaType));
        if (visible) {
            try {
                String contentString = new String(content, contentEncoding);
                Stream.of(contentString.split("\r\n|\r|\n")).forEach(line -> log.debug("{} {}", prefix, line));
            } catch (UnsupportedEncodingException e) {
                log.debug("{} [{} bytes content]", prefix, content.length);
            }
        } else {
            log.debug("{} [{} bytes content]", prefix, content.length);
        }
    }

    private static ContentCachingRequestWrapper wrapRequest(HttpServletRequest request) {
        if (request instanceof ContentCachingRequestWrapper) {
            return (ContentCachingRequestWrapper) request;
        } else {
            return new ContentCachingRequestWrapper(request);
        }
    }

    private static ContentCachingResponseWrapper wrapResponse(HttpServletResponse response) {
        if (response instanceof ContentCachingResponseWrapper) {
            return (ContentCachingResponseWrapper) response;
        } else {
            return new ContentCachingResponseWrapper(response);
        }
    }
}
