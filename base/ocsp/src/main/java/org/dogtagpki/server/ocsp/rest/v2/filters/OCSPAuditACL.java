package org.dogtagpki.server.ocsp.rest.v2.filters;

import javax.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.AuditACL;

@WebFilter(servletNames = "ocspAudit")
public class OCSPAuditACL extends AuditACL {
    private static final long serialVersionUID = 1L;
}
