package org.dogtagpki.server.ca.rest.v2.filters;

import jakarta.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.GroupACL;

@WebFilter(servletNames = "caGroup")
public class CAGroupACL extends GroupACL {
    private static final long serialVersionUID = 1L;
}
