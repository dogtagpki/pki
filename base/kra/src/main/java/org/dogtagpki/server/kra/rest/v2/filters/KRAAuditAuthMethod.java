package org.dogtagpki.server.kra.rest.v2.filters;

import jakarta.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.AuthMethodFilter;

@WebFilter(servletNames = "kraAudit")
public class KRAAuditAuthMethod extends AuthMethodFilter {
    private static final long serialVersionUID = 1L;
}
