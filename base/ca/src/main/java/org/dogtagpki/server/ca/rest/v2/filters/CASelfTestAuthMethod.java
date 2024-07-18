package org.dogtagpki.server.ca.rest.v2.filters;

import javax.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.SelfTestAuthMethod;

@WebFilter(servletNames = "caSelfTests")
public class CASelfTestAuthMethod extends SelfTestAuthMethod {
    private static final long serialVersionUID = 1L;
}
