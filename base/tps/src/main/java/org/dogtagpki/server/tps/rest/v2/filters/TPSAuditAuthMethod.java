package org.dogtagpki.server.tps.rest.v2.filters;

import jakarta.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.AuthMethodFilter;

@WebFilter(servletNames = "tpsAudit")
public class TPSAuditAuthMethod extends AuthMethodFilter {
    private static final long serialVersionUID = 1L;
}
