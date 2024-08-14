package com.netscape.certsrv.base;

import javax.servlet.http.HttpServletResponse;

public class ServiceUnavailableException extends PKIException {

    private static final long serialVersionUID = -9160776882517621347L;

    public ServiceUnavailableException(String message) {
        super(HttpServletResponse.SC_SERVICE_UNAVAILABLE, message);
    }

    public ServiceUnavailableException(String message, Throwable cause) {
        super(HttpServletResponse.SC_SERVICE_UNAVAILABLE, message, cause);
    }

    public ServiceUnavailableException(Data data) {
        super(data);
    }
}
