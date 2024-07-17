package org.dogtagpki.server.tks.rest.v2.filters;

import javax.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.UserAuthMethod;

@WebFilter(servletNames = "tksUser")
public class UserTKSAuthMethod extends UserAuthMethod {
    private static final long serialVersionUID = 1L;
}
