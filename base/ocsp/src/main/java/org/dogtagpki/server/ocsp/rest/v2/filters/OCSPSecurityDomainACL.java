package org.dogtagpki.server.ocsp.rest.v2.filters;

import javax.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.SecurityDomainACL;

@WebFilter(servletNames = "ocspSecurityDomain")
public class OCSPSecurityDomainACL extends SecurityDomainACL {
    private static final long serialVersionUID = 1L;
}
