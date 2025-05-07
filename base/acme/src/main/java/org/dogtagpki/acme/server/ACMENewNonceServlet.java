//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.dogtagpki.acme.ACMENonce;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.WebAction;

/**
 * ACME new nonce.
 *
 * @author Endi S. Dewata
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
@WebServlet(
        name = "acmeNewNonceServlet",
        urlPatterns = "/new-nonce/*")
public class ACMENewNonceServlet extends ACMEServlet {

    private static final long serialVersionUID = 1L;

    private static Logger logger = LoggerFactory.getLogger(ACMENewNonceServlet.class);

    @WebAction(method = HttpMethod.HEAD, paths = {""})
    public void headNewNonce(HttpServletRequest request, HttpServletResponse response) throws Exception {
        createNonce(response);
        addIndex(request, response);
    }

    @WebAction(method = HttpMethod.GET, paths = {""})
    public void getNewNonce(HttpServletRequest request, HttpServletResponse response) throws Exception {
        createNonce(response);
        addIndex(request, response);
        response.setStatus(HttpServletResponse.SC_NO_CONTENT);
    }

    private void createNonce(HttpServletResponse response) throws Exception {

        logger.info("Creating nonce");

        ACMENonce nonce = engine.createNonce();
        response.setHeader("Replay-Nonce", nonce.getID());
        response.setHeader("Cache-Control", "no-store");
    }

}