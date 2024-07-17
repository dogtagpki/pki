package org.dogtagpki.server.ca.rest.v2.filters;

import javax.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.AccountAuthMethod;

@WebFilter(servletNames = "caAccount")
public class AccountCAAuthMethod extends AccountAuthMethod {
    private static final long serialVersionUID = 1L;
}
