package com.netscape.certsrv.base;

import javax.servlet.http.HttpServletResponse;

public class ResourceNotFoundException extends PKIException {

    private static final long serialVersionUID = 2283994502912462263L;

    public ResourceNotFoundException(String message) {
        super(HttpServletResponse.SC_NOT_FOUND, message);
    }

    public ResourceNotFoundException(String message, Throwable cause) {
        super(HttpServletResponse.SC_NOT_FOUND, message, cause);
    }

    public ResourceNotFoundException(Data data) {
        super(data);
    }

    @Override
    public Data getData() {
        return super.getData();
    }
}
