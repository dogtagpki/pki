package org.dogtagpki.server.ocsp.rest.v2.filters;

import javax.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.AccountAuthMethod;

@WebFilter(servletNames = "ocspAccount")
public class OCSPAccountAuthMethod extends AccountAuthMethod {
    private static final long serialVersionUID = 1L;
}
