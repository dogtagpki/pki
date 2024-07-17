package org.dogtagpki.server.kra.rest.v2.filters;

import javax.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.UserAuthMethod;

@WebFilter(servletNames = "kraUser")
public class UserKRAAuthMethod extends UserAuthMethod {
    private static final long serialVersionUID = 1L;
}
