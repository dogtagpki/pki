package org.dogtagpki.server.tps.rest.v2.filters;

import jakarta.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.AccountACL;

@WebFilter(servletNames = "tpsAccount")
public class TPSAccountACL extends AccountACL {
    private static final long serialVersionUID = 1L;
}
