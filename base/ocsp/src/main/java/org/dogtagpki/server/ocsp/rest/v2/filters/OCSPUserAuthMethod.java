package org.dogtagpki.server.ocsp.rest.v2.filters;

import jakarta.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.UserAuthMethod;

@WebFilter(servletNames = "ocspUser")
public class OCSPUserAuthMethod extends UserAuthMethod {
    private static final long serialVersionUID = 1L;
}
