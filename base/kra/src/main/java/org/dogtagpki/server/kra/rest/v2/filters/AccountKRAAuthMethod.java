package org.dogtagpki.server.kra.rest.v2.filters;

import javax.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.AccountAuthMethod;

@WebFilter(servletNames = "kraAccount")
public class AccountKRAAuthMethod extends AccountAuthMethod {
    private static final long serialVersionUID = 1L;
}
