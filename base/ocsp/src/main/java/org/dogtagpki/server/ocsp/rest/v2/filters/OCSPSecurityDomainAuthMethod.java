package org.dogtagpki.server.ocsp.rest.v2.filters;

import javax.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.SecurityDomainAuthMethod;

@WebFilter(servletNames = "ocspSecurityDomain")
public class OCSPSecurityDomainAuthMethod extends SecurityDomainAuthMethod {
    private static final long serialVersionUID = 1L;
}
