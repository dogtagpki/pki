package org.dogtagpki.server.tks.rest.v2.filters;

import jakarta.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.UserAuthMethod;

@WebFilter(servletNames = "tksUser")
public class TKSUserAuthMethod extends UserAuthMethod {
    private static final long serialVersionUID = 1L;
}
