package org.dogtagpki.server.tks.rest.v2.filters;

import javax.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.UserACL;

@WebFilter(servletNames = "tksUser")
public class UserTKSACL extends UserACL {
    private static final long serialVersionUID = 1L;
}
