package org.dogtagpki.server.tps.rest.v2.filters;

import javax.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.GroupACL;

@WebFilter(servletNames = "tpsGroup")
public class TPSGroupACL extends GroupACL {
    private static final long serialVersionUID = 1L;
}
