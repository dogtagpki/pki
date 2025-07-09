package org.dogtagpki.server.tps.rest.v2.filters;

import jakarta.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.GroupAuthMethod;

@WebFilter(servletNames = "tpsGroup")
public class TPSGroupAuthMethod extends GroupAuthMethod {
    private static final long serialVersionUID = 1L;
}
