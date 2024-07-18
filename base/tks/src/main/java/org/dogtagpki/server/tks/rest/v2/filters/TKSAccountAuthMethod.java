package org.dogtagpki.server.tks.rest.v2.filters;

import javax.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.AccountAuthMethod;

@WebFilter(servletNames = "tksAccount")
public class TKSAccountAuthMethod extends AccountAuthMethod {
    private static final long serialVersionUID = 1L;
}
