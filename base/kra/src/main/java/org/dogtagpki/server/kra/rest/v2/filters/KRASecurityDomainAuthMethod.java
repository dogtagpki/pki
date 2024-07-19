package org.dogtagpki.server.kra.rest.v2.filters;

import javax.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.SecurityDomainAuthMethod;

@WebFilter(servletNames = "kraSecurityDomain")
public class KRASecurityDomainAuthMethod extends SecurityDomainAuthMethod {
    private static final long serialVersionUID = 1L;
}
