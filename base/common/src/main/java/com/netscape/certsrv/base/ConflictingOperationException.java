package com.netscape.certsrv.base;

import javax.ws.rs.core.Response;

public class ConflictingOperationException extends PKIException {

    private static final long serialVersionUID = -5780172673428115193L;

    public ConflictingOperationException(String message) {
        super(Response.Status.CONFLICT, message);
    }

    public ConflictingOperationException(String message, Throwable cause) {
        super(Response.Status.CONFLICT, message, cause);
    }

    public ConflictingOperationException(Data data) {
        super(data);
    }
}
