package org.dogtagpki.server.ca.rest.v2.filters;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.ACLFilter;

@WebFilter(servletNames = "caKraConnector")
public class KRAConnectorACL extends ACLFilter {
    private static final long serialVersionUID = 1L;
    @Override
    public void init() throws ServletException {
        setAcl("kraconnectors");
    }
}
