package com.netscape.certsrv.base;

import javax.servlet.http.HttpServletResponse;

public class ForbiddenException extends PKIException {
    private static final long serialVersionUID = 3199015969025638546L;

    public ForbiddenException(String message) {
        super(HttpServletResponse.SC_FORBIDDEN, message);
    }

    public ForbiddenException(String message, Throwable cause) {
        super(HttpServletResponse.SC_FORBIDDEN, message, cause);
    }

    public ForbiddenException(Data data) {
        super(data);
    }
}
