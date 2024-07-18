package org.dogtagpki.server.kra.rest.v2.filters;

import javax.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.SelfTestACL;

@WebFilter(servletNames = "kraSelfTests")
public class KRASelfTestACL extends SelfTestACL {
    private static final long serialVersionUID = 1L;
}
