package org.dogtagpki.server.ocsp.rest.v2.filters;

import jakarta.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.SelfTestACL;

@WebFilter(servletNames = "ocspSelfTests")
public class OCSPSelfTestACL extends SelfTestACL {
    private static final long serialVersionUID = 1L;
}
