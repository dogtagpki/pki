package org.dogtagpki.server.tps.rest.v2.filters;

import jakarta.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.UserAuthMethod;

@WebFilter(servletNames = "tpsUser")
public class TPSUserAuthMethod extends UserAuthMethod {
    private static final long serialVersionUID = 1L;
}
