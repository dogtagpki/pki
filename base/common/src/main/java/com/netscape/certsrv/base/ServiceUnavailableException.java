package com.netscape.certsrv.base;

import javax.ws.rs.core.Response;

public class ServiceUnavailableException extends PKIException {

    private static final long serialVersionUID = -9160776882517621347L;

    public ServiceUnavailableException(String message) {
        super(Response.Status.SERVICE_UNAVAILABLE, message);
    }

    public ServiceUnavailableException(String message, Throwable cause) {
        super(Response.Status.SERVICE_UNAVAILABLE, message, cause);
    }

}
