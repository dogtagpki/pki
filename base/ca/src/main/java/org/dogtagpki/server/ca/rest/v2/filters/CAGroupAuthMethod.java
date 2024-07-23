package org.dogtagpki.server.ca.rest.v2.filters;

import javax.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.GroupAuthMethod;

@WebFilter(servletNames = "caGroup")
public class CAGroupAuthMethod extends GroupAuthMethod {
    private static final long serialVersionUID = 1L;
}
