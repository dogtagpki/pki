package com.netscape.certsrv.base;

import org.apache.http.HttpStatus;

public class ForbiddenException extends PKIException {
    private static final long serialVersionUID = 3199015969025638546L;

    public ForbiddenException(String message) {
        super(HttpStatus.SC_FORBIDDEN, message);
    }

    public ForbiddenException(String message, Throwable cause) {
        super(HttpStatus.SC_FORBIDDEN, message, cause);
    }

    public ForbiddenException(Data data) {
        super(data);
    }
}
