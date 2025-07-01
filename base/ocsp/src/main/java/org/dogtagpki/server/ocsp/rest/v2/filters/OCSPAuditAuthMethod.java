package org.dogtagpki.server.ocsp.rest.v2.filters;

import jakarta.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.AuthMethodFilter;

@WebFilter(servletNames = "ocspAudit")
public class OCSPAuditAuthMethod extends AuthMethodFilter {
    private static final long serialVersionUID = 1L;
}
