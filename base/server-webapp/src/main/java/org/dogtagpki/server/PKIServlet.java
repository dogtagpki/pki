//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server;

import java.io.IOException;

import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class PKIServlet extends HttpServlet {

    public static final long serialVersionUID = 1L;

    public PKIEngine getPKIEngine() {
        ServletContext servletContext = getServletContext();
        return (PKIEngine) servletContext.getAttribute("engine");
    }

    public void get(HttpServletRequest request, HttpServletResponse response) throws Exception {
        response.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
    }

    public void post(HttpServletRequest request, HttpServletResponse response) throws Exception {
        response.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
    }

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            get(request, response);

        } catch (ServletException | IOException e) {
            throw e;

        } catch (Exception e) {
            throw new ServletException(e);
        }
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            post(request, response);

        } catch (ServletException | IOException e) {
            throw e;

        } catch (Exception e) {
            throw new ServletException(e);
        }
    }
}
