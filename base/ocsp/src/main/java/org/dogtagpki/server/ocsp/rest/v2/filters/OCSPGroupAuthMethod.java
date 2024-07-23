package org.dogtagpki.server.ocsp.rest.v2.filters;

import javax.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.GroupAuthMethod;

@WebFilter(servletNames = "ocspGroup")
public class OCSPGroupAuthMethod extends GroupAuthMethod {
    private static final long serialVersionUID = 1L;
}
