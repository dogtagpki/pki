package com.netscape.certsrv.base;

import javax.ws.rs.core.Response;

public class ResourceNotFoundException extends PKIException {

    private static final long serialVersionUID = 2283994502912462263L;

    public ResourceNotFoundException(String message) {
        super(Response.Status.NOT_FOUND, message);
    }

    public ResourceNotFoundException(String message, Throwable cause) {
        super(Response.Status.NOT_FOUND, message, cause);
    }

    public ResourceNotFoundException(Data data) {
        super(data);
    }

    public Data getData() {
        return super.getData();
    }
}
