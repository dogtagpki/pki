package org.dogtagpki.server.kra.rest.v2.filters;

import jakarta.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.GroupAuthMethod;

@WebFilter(servletNames = "kraGroup")
public class KRAGroupAuthMethod extends GroupAuthMethod {
    private static final long serialVersionUID = 1L;
}
