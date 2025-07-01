package org.dogtagpki.server.tks.rest.v2.filters;

import jakarta.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.AccountACL;

@WebFilter(servletNames = "tksAccount")
public class TKSAccountACL extends AccountACL {
    private static final long serialVersionUID = 1L;
}
