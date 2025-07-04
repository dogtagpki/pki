//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.acme.server;

import java.net.URISyntaxException;

import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.apache.http.client.utils.URIBuilder;
import org.dogtagpki.server.rest.v2.PKIServlet;

public class ACMEServlet extends PKIServlet {

    private static final long serialVersionUID = 1L;

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
