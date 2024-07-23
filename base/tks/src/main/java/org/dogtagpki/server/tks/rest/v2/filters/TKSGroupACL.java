package org.dogtagpki.server.tks.rest.v2.filters;

import javax.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.GroupACL;

@WebFilter(servletNames = "tksGroup")
public class TKSGroupACL extends GroupACL {
    private static final long serialVersionUID = 1L;
}
