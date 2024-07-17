package org.dogtagpki.server.kra.rest.v2.filters;

import javax.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.UserACL;

@WebFilter(servletNames = "kraUser")
public class UserKRAACL extends UserACL {
    private static final long serialVersionUID = 1L;
}
