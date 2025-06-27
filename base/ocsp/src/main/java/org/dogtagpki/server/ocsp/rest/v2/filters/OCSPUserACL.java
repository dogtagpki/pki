package org.dogtagpki.server.ocsp.rest.v2.filters;

import jakarta.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.UserACL;

@WebFilter(servletNames = "ocspUser")
public class OCSPUserACL extends UserACL {
    private static final long serialVersionUID = 1L;
}
