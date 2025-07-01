package org.dogtagpki.server.tks.rest.v2.filters;

import jakarta.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.SelfTestACL;

@WebFilter(servletNames = "tksSelfTests")
public class TKSSelfTestACL extends SelfTestACL {
    private static final long serialVersionUID = 1L;
}
