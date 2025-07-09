package org.dogtagpki.server.ca.rest.v2.filters;

import jakarta.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.AccountACL;

@WebFilter(servletNames = "caAccount")
public class CAAccountACL extends AccountACL {
    private static final long serialVersionUID = 1L;
}
