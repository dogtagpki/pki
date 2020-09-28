package com.netscape.certsrv.base;

import javax.ws.rs.core.Response;

public class ForbiddenException extends PKIException {
    private static final long serialVersionUID = 3199015969025638546L;

    public ForbiddenException(String message) {
        super(Response.Status.FORBIDDEN, message);
    }

    public ForbiddenException(String message, Throwable cause) {
        super(Response.Status.FORBIDDEN, message, cause);
    }

    public ForbiddenException(Data data) {
        super(data);
    }
}
