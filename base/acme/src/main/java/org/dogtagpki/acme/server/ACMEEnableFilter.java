//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpFilter;
import javax.servlet.http.HttpServletResponse;

import org.dogtagpki.acme.database.ACMEDatabase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
/**
 * ACME filter.
 *
 * @author Fraser Tweedale
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
@WebFilter(servletNames = {"acmeDirectoryServlet", "acmeNewNonceServlet", "acmeNewAccountServlet",
        "acmeNewOrderServlet", "acmeAuthorizationServlet", "acmeChallangeServlet", "acmeOrderServlet",
        "acmeCertificateServlet", "acmeRevokeCertificateServlet", "acmeAccountServlet"})
public class ACMEEnableFilter extends HttpFilter {

    private static final long serialVersionUID = 1L;
    private static Logger logger = LoggerFactory.getLogger(ACMEEnableFilter.class);
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        ACMEEngine engine = ACMEEngine.getInstance();
        ACMEDatabase database = engine.getDatabase();

        Boolean enabled = null;
        try {
            // get config property from database
            enabled = database.getEnabled();
        } catch (Exception e) {
            throw new IOException("Unable to access ACME database: " + e.getMessage(), e);
        }

        if (enabled == null) {
            // config property is unset in database, get it from config file instead
            enabled = engine.isEnabled();
        }

        if (!enabled) {
            HttpServletResponse resp =(HttpServletResponse) response;

            logger.info("ACMEEnableFilter: ACME service is disabled");
            resp.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
            resp.getWriter().write("ACME service is disabled");
            return;
        }
        chain.doFilter(request, response);
    }

}
