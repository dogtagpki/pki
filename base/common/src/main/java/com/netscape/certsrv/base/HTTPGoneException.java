package com.netscape.certsrv.base;

import org.apache.hc.core5.http.HttpStatus;

public class HTTPGoneException extends PKIException {

    private static final long serialVersionUID = 1256191208802745690L;

    public HTTPGoneException(String message) {
        super(HttpStatus.SC_GONE, message);
    }

    public HTTPGoneException(String message, Throwable cause) {
        super(HttpStatus.SC_GONE, message, cause);
    }

    public HTTPGoneException(Data data) {
        super(data);
    }
}
