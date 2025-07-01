package org.dogtagpki.server.ca.rest.v2.filters;

import jakarta.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.AccountAuthMethod;

@WebFilter(servletNames = "caAccount")
public class CAAccountAuthMethod extends AccountAuthMethod {
    private static final long serialVersionUID = 1L;
}
