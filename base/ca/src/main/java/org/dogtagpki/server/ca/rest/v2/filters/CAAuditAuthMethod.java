package org.dogtagpki.server.ca.rest.v2.filters;

import jakarta.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.AuthMethodFilter;

@WebFilter(servletNames = "caAudit")
public class CAAuditAuthMethod extends AuthMethodFilter {
    private static final long serialVersionUID = 1L;
}
