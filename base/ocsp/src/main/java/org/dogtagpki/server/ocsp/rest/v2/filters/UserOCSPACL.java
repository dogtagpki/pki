package org.dogtagpki.server.ocsp.rest.v2.filters;

import javax.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.UserACL;

@WebFilter(servletNames = "ocspUser")
public class UserOCSPACL extends UserACL {
    private static final long serialVersionUID = 1L;
}
