package org.dogtagpki.server.tks.rest.v2.filters;

import javax.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.SelfTestAuthMethod;

@WebFilter(servletNames = "tksSelfTests")
public class TKSSelfTestAuthMethod extends SelfTestAuthMethod {
    private static final long serialVersionUID = 1L;
}
