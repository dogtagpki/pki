//
//Copyright Red Hat, Inc.
//
//SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.dogtagpki.acme.database.ACMEDatabase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.WebAction;

/**
 * ACME disable.
 *
 * @author Endi S. Dewata
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
@WebServlet(
        name = "acmeDisableServlet",
        urlPatterns = "/disable/*")
public class ACMEDisableServlet extends ACMEServlet {

    private static final long serialVersionUID = 1L;
    private static Logger logger = LoggerFactory.getLogger(ACMEEnableServlet.class);

    @WebAction(method = HttpMethod.POST, paths = {""})
    public void enable(HttpServletRequest request, HttpServletResponse response) throws Exception {
        logger.info("Disabling ACME services");

        ACMEDatabase database = engine.getDatabase();
        database.setEnabled(false);
    }
}
