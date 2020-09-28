package com.netscape.certsrv.base;

import javax.ws.rs.core.Response;

public class HTTPGoneException extends PKIException {

    private static final long serialVersionUID = 1256191208802745690L;

    public HTTPGoneException(String message) {
        super(Response.Status.GONE, message);
    }

    public HTTPGoneException(String message, Throwable cause) {
        super(Response.Status.GONE, message, cause);
    }

    public HTTPGoneException(Data data) {
        super(data);
    }
}
