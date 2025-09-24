package org.dogtagpki.server.kra.rest.v2.filters;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.ACLFilter;

@WebFilter(servletNames = "kraKey")
public class KeyACL extends ACLFilter {
    private static final long serialVersionUID = 1L;
    @Override
    public void init() throws ServletException {
        setAcl("keys");
    }
}
