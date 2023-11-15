//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca;

import java.io.IOException;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author Marco Fargetta <mfargett@redhat.com>
 */
public class CAServlet extends HttpServlet {
    public static final long serialVersionUID = 1L;


    public void get(HttpServletRequest request, HttpServletResponse response) throws Exception {
    }

    public void post(HttpServletRequest request, HttpServletResponse response) throws Exception {
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

    public CAEngine getCAEngine() {
        ServletContext servletContext = getServletContext();
        return (CAEngine) servletContext.getAttribute("engine");
    }
}
