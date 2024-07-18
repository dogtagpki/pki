package org.dogtagpki.server.tks.rest.v2.filters;

import javax.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.AuditACL;

@WebFilter(servletNames = "tksAudit")
public class TKSAuditACL extends AuditACL {
    private static final long serialVersionUID = 1L;
}
