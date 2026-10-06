//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import java.io.IOException;
import java.net.URISyntaxException;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.http.client.utils.URIBuilder;
import org.dogtagpki.acme.ACMENonce;
import org.dogtagpki.server.rest.v2.PKIServlet;

import com.netscape.certsrv.base.PKIException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ACMEServlet extends PKIServlet {

    private static final long serialVersionUID = 1L;

    private static Logger logger = LoggerFactory.getLogger(ACMEServlet.class);

    protected ACMEEngine engine;

    @Override
    public void init() throws ServletException {
        super.init();
        engine = getACMEEngine();
    }

    public ACMEEngine getACMEEngine() {
        ServletContext servletContext = getServletContext();
        return (ACMEEngine) servletContext.getAttribute("engine");
    }

    @Override
    protected void handlePKIException(
            HttpServletRequest request,
            HttpServletResponse response,
            PKIException exception) throws IOException {

        try {
            ACMENonce nonce = engine.createNonce();
            response.setHeader("Replay-Nonce", nonce.getID());

        } catch (Exception e) {
            logger.error("Unable to create nonce: " + e.getMessage(), e);
        }

        super.handlePKIException(request, response, exception);
    }

    protected void addIndex(HttpServletRequest request, HttpServletResponse response) throws URISyntaxException {
        URIBuilder uriBuilder = new URIBuilder(request.getRequestURL().toString());
        uriBuilder.removeQuery();
        uriBuilder.setPath(request.getContextPath() + "/directory");
        StringBuilder link = new StringBuilder("<")
                .append(uriBuilder.build().toString())
                .append(">;rel=\"index\"");
        response.addHeader("Link", link.toString());
    }

}
