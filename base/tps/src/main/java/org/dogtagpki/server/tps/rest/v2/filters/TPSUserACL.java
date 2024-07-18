package org.dogtagpki.server.tps.rest.v2.filters;

import javax.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.UserACL;

@WebFilter(servletNames = "tpsUser")
public class TPSUserACL extends UserACL {
    private static final long serialVersionUID = 1L;
}
