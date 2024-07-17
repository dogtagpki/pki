package org.dogtagpki.server.rest.v2.filters;

import javax.servlet.ServletException;

public class UserACL extends ACLFilter {
    private static final long serialVersionUID = 1L;

    @Override
    public void init() throws ServletException {
        setAcl("users");
    }

}
