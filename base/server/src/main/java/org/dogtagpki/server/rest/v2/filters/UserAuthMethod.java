package org.dogtagpki.server.rest.v2.filters;

import javax.servlet.ServletException;

public class UserAuthMethod extends AuthMethodFilter {
    private static final long serialVersionUID = 1L;

    @Override
    public void init() throws ServletException {
        setAuthMethod("users");
    }

}
