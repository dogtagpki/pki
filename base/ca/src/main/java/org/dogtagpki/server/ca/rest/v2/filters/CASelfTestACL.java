package org.dogtagpki.server.ca.rest.v2.filters;

import jakarta.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.SelfTestACL;

@WebFilter(servletNames = "caSelfTests")
public class CASelfTestACL extends SelfTestACL {
    private static final long serialVersionUID = 1L;
}
