package org.dogtagpki.server.kra.rest.v2.filters;

import jakarta.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.GroupACL;

@WebFilter(servletNames = "kraGroup")
public class KRAGroupACL extends GroupACL {
    private static final long serialVersionUID = 1L;
}
