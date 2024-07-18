package org.dogtagpki.server.kra.rest.v2.filters;

import javax.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.AuditACL;

@WebFilter(servletNames = "kraAudit")
public class KRAAuditACL extends AuditACL {
    private static final long serialVersionUID = 1L;
}
