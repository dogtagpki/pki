package org.dogtagpki.server.kra.rest.v2.filters;

import javax.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.SelfTestAuthMethod;

@WebFilter(servletNames = "kraSelfTests")
public class KRASelfTestAuthMethod extends SelfTestAuthMethod {
    private static final long serialVersionUID = 1L;
}
