package org.dogtagpki.server.ocsp.rest.v2.filters;

import javax.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.SelfTestAuthMethod;

@WebFilter(servletNames = "ocspSelfTests")
public class SelfTestOCSPAuthMethod extends SelfTestAuthMethod {
    private static final long serialVersionUID = 1L;
}
