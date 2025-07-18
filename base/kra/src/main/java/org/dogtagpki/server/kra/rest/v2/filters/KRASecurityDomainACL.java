package org.dogtagpki.server.kra.rest.v2.filters;

import jakarta.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.SecurityDomainACL;

@WebFilter(servletNames = "kraSecurityDomain")
public class KRASecurityDomainACL extends SecurityDomainACL {
    private static final long serialVersionUID = 1L;
}
