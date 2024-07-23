package org.dogtagpki.server.tks.rest.v2.filters;

import javax.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.GroupAuthMethod;

@WebFilter(servletNames = "tksGroup")
public class TKSGroupAuthMethod extends GroupAuthMethod {
    private static final long serialVersionUID = 1L;
}
