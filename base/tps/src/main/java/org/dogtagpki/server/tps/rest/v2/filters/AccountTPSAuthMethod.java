package org.dogtagpki.server.tps.rest.v2.filters;

import javax.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.filters.AccountAuthMethod;

@WebFilter(servletNames = "tpsAccount")
public class AccountTPSAuthMethod extends AccountAuthMethod {
    private static final long serialVersionUID = 1L;
}
