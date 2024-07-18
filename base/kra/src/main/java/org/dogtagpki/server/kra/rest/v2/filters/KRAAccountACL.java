package org.dogtagpki.server.kra.rest.v2.filters;

import javax.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.AccountACL;

@WebFilter(servletNames = "kraAccount")
public class KRAAccountACL extends AccountACL {
    private static final long serialVersionUID = 1L;
}
