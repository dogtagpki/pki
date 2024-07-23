package org.dogtagpki.server.ocsp.rest.v2.filters;

import javax.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.GroupACL;

@WebFilter(servletNames = "ocspGroup")
public class OCSPGroupACL extends GroupACL {
    private static final long serialVersionUID = 1L;
}
