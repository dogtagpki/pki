package org.dogtagpki.server.ca.rest.v2.filters;

import jakarta.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.UserACL;

@WebFilter(servletNames = "caUser")
public class CAUserACL extends UserACL {
    private static final long serialVersionUID = 1L;
}
