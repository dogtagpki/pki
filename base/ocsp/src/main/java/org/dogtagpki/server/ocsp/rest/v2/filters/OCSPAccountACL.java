package org.dogtagpki.server.ocsp.rest.v2.filters;

import jakarta.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.AccountACL;

@WebFilter(servletNames = "ocspAccount")
public class OCSPAccountACL extends AccountACL {
    private static final long serialVersionUID = 1L;
}
