package org.dogtagpki.server.kra.rest.v2.filters;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.ACLFilter;

@WebFilter(servletNames = "kraKeyRequest")
public class KeyRequestACL extends ACLFilter {
    private static final long serialVersionUID = 1L;
    @Override
    public void init() throws ServletException {
        setAcl("keyrequests");
    }
}
