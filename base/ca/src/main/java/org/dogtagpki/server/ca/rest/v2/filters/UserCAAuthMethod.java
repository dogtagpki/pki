package org.dogtagpki.server.ca.rest.v2.filters;

import javax.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.UserAuthMethod;

@WebFilter(servletNames = "caUser")
public class UserCAAuthMethod extends UserAuthMethod {
    private static final long serialVersionUID = 1L;
}
