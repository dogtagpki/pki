package com.netscape.certsrv.base;

import org.apache.http.HttpStatus;

public class ConflictingOperationException extends PKIException {

    private static final long serialVersionUID = -5780172673428115193L;

    public ConflictingOperationException(String message) {
        super(HttpStatus.SC_CONFLICT, message);
    }

    public ConflictingOperationException(String message, Throwable cause) {
        super(HttpStatus.SC_CONFLICT, message, cause);
    }

    public ConflictingOperationException(Data data) {
        super(data);
    }
}
