package org.dogtagpki.server.tps.rest.v2.filters;

import javax.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.SelfTestACL;

@WebFilter(servletNames = "tpsSelfTests")
public class SelfTestTPSACL extends SelfTestACL {
    private static final long serialVersionUID = 1L;
}
