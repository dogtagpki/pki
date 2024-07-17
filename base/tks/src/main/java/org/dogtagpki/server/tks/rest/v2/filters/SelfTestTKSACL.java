package org.dogtagpki.server.tks.rest.v2.filters;

import javax.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.SelfTestACL;

@WebFilter(servletNames = "tksSelfTests")
public class SelfTestTKSACL extends SelfTestACL {
    private static final long serialVersionUID = 1L;
}
