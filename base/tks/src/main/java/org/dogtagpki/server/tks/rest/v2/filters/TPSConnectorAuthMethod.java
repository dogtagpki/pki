package org.dogtagpki.server.tks.rest.v2.filters;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.AuthMethodFilter;

@WebFilter(servletNames = "tksTPSConnector")
public class TPSConnectorAuthMethod extends AuthMethodFilter{
    private static final long serialVersionUID = 1L;

    @Override
    public void init() throws ServletException {
        setAuthMethod("tpsconnectors");
    }
}
