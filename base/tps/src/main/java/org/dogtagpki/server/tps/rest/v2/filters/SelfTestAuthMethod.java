package org.dogtagpki.server.tps.rest.v2.filters;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebFilter;

import org.dogtagpki.server.rest.v2.AuthMethodFilter;

@WebFilter(servletNames = "tpsSelfTests")
public class SelfTestAuthMethod extends AuthMethodFilter {
    private static final long serialVersionUID = 1L;

    @Override
    public void init() throws ServletException {
        setAuthMethod("selftests.read");
    }

}
