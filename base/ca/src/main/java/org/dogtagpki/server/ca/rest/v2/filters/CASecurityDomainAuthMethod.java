package org.dogtagpki.server.ca.rest.v2.filters;

import jakarta.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.SecurityDomainAuthMethod;

@WebFilter(servletNames = "caSecurityDomain")
public class CASecurityDomainAuthMethod extends SecurityDomainAuthMethod {
    private static final long serialVersionUID = 1L;
}
