package com.netscape.certsrv.base;

import javax.servlet.http.HttpServletResponse;

public class ConflictingOperationException extends PKIException {

    private static final long serialVersionUID = -5780172673428115193L;

    public ConflictingOperationException(String message) {
        super(HttpServletResponse.SC_CONFLICT, message);
    }

    public ConflictingOperationException(String message, Throwable cause) {
        super(HttpServletResponse.SC_CONFLICT, message, cause);
    }

    public ConflictingOperationException(Data data) {
        super(data);
    }
}
