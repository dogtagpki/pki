package org.dogtagpki.server.ca.rest.v2.filters;

import javax.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.AccountACL;

@WebFilter(servletNames = "caAccount")
public class AccountCAACL extends AccountACL {
    private static final long serialVersionUID = 1L;
}
