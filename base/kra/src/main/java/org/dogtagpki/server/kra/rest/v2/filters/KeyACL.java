package org.dogtagpki.server.kra.rest.v2.filters;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.ACLFilter;

@WebFilter(servletNames = "kraKey")
public class KeyACL extends ACLFilter {
    private static final long serialVersionUID = 1L;
    @Override
    public void init() throws ServletException {
        setAcl("keys");
    }
}
