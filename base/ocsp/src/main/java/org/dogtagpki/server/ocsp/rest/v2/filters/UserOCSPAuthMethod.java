package org.dogtagpki.server.ocsp.rest.v2.filters;

import javax.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.UserAuthMethod;

@WebFilter(servletNames = "ocspUser")
public class UserOCSPAuthMethod extends UserAuthMethod {
    private static final long serialVersionUID = 1L;
}
