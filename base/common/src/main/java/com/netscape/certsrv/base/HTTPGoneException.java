package com.netscape.certsrv.base;

import javax.servlet.http.HttpServletResponse;

public class HTTPGoneException extends PKIException {

    private static final long serialVersionUID = 1256191208802745690L;

    public HTTPGoneException(String message) {
        super(HttpServletResponse.SC_GONE, message);
    }

    public HTTPGoneException(String message, Throwable cause) {
        super(HttpServletResponse.SC_GONE, message, cause);
    }

    public HTTPGoneException(Data data) {
        super(data);
    }
}
