package org.dogtagpki.server.ca.rest.v2.filters;

import javax.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.SelfTestACL;

@WebFilter(servletNames = "caSelfTests")
public class SelfTestCAACL extends SelfTestACL {
    private static final long serialVersionUID = 1L;
}
