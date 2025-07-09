package org.dogtagpki.server.tks.rest.v2.filters;

import jakarta.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.AuthMethodFilter;

@WebFilter(servletNames = "tksAudit")
public class TKSAuditAuthMethod extends AuthMethodFilter {
    private static final long serialVersionUID = 1L;
}
