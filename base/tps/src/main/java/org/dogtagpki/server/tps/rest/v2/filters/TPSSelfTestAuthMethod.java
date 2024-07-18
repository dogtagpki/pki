package org.dogtagpki.server.tps.rest.v2.filters;

import javax.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.SelfTestAuthMethod;

@WebFilter(servletNames = "tpsSelfTests")
public class TPSSelfTestAuthMethod extends SelfTestAuthMethod {
    private static final long serialVersionUID = 1L;
}
