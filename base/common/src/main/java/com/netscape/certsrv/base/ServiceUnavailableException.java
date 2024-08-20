package com.netscape.certsrv.base;

import org.apache.http.HttpStatus;

public class ServiceUnavailableException extends PKIException {

    private static final long serialVersionUID = -9160776882517621347L;

    public ServiceUnavailableException(String message) {
        super(HttpStatus.SC_SERVICE_UNAVAILABLE, message);
    }

    public ServiceUnavailableException(String message, Throwable cause) {
        super(HttpStatus.SC_SERVICE_UNAVAILABLE, message, cause);
    }

    public ServiceUnavailableException(Data data) {
        super(data);
    }
}
