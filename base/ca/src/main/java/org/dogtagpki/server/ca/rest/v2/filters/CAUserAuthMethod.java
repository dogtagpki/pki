package org.dogtagpki.server.ca.rest.v2.filters;

import jakarta.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.UserAuthMethod;

@WebFilter(servletNames = "caUser")
public class CAUserAuthMethod extends UserAuthMethod {
    private static final long serialVersionUID = 1L;
}
