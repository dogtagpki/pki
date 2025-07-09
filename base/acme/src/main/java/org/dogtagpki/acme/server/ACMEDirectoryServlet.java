//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import java.io.PrintWriter;
import java.net.URL;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.apache.http.client.utils.URIBuilder;
import org.dogtagpki.acme.ACMEDirectory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.WebAction;

/**
 * ACME directory.
 *
 * @author Endi S. Dewata
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
@WebServlet(
        name = "acmeDirectoryServlet",
        urlPatterns = "/directory/*")
public class ACMEDirectoryServlet extends ACMEServlet {

    private static final long serialVersionUID = 1L;
    private static Logger logger = LoggerFactory.getLogger(ACMEDirectoryServlet.class);

    @WebAction(method = HttpMethod.GET, paths = {""})
    public void getDirectory(HttpServletRequest request, HttpServletResponse response) throws Exception {
        logger.info("Creating directory");

        URL baseURL = engine.getBaseURL();
        URIBuilder uriBuilder;
        if (baseURL != null) {
            uriBuilder = new URIBuilder(baseURL.toURI());
        } else {
            uriBuilder = new URIBuilder(request.getRequestURL().toString());
        }
        uriBuilder.removeQuery();
        String basePath = request.getContextPath();

        ACMEDirectory directory = new ACMEDirectory();

        directory.setMetadata(engine.getMetadata());

        uriBuilder.setPath(basePath + "/new-nonce");
        directory.setNewNonce(uriBuilder.build());

        uriBuilder.setPath(basePath + "/new-account");
        directory.setNewAccount(uriBuilder.build());

        uriBuilder.setPath(basePath + "/new-order");
        directory.setNewOrder(uriBuilder.build());

        uriBuilder.setPath(basePath + "/revoke-cert");
        directory.setRevokeCert(uriBuilder.build());
        logger.info("Directory:\n" + directory);

        PrintWriter out = response.getWriter();
        out.println(directory.toJSON());
    }
}
