package org.dogtagpki.server.tps.rest.v2.filters;

import jakarta.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.AuditACL;

@WebFilter(servletNames = "tpsAudit")
public class TPSAuditACL extends AuditACL {
    private static final long serialVersionUID = 1L;
}
