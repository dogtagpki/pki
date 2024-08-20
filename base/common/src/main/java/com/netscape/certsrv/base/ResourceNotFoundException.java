package com.netscape.certsrv.base;

import org.apache.http.HttpStatus;

public class ResourceNotFoundException extends PKIException {

    private static final long serialVersionUID = 2283994502912462263L;

    public ResourceNotFoundException(String message) {
        super(HttpStatus.SC_NOT_FOUND, message);
    }

    public ResourceNotFoundException(String message, Throwable cause) {
        super(HttpStatus.SC_NOT_FOUND, message, cause);
    }

    public ResourceNotFoundException(Data data) {
        super(data);
    }

    @Override
    public Data getData() {
        return super.getData();
    }
}
