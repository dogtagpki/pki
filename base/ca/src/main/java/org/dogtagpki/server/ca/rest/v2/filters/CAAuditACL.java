package org.dogtagpki.server.ca.rest.v2.filters;

import jakarta.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.AuditACL;

@WebFilter(servletNames = "caAudit")
public class CAAuditACL extends AuditACL {
    private static final long serialVersionUID = 1L;
}
