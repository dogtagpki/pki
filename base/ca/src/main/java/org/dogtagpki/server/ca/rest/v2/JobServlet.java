//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.ca.rest.v2;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.dogtagpki.server.rest.v2.JobServletBase;

import com.netscape.certsrv.base.SupportedPath;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
@WebServlet(
        name = "caJobs",
        urlPatterns = "/v2/jobs/*")
public class JobServlet extends CAServlet {
    private static final long serialVersionUID = 1L;

    @Override
    @SupportedPath(method = HttpMethod.GET, paths = { "/", "/{}"})
    public void get(HttpServletRequest request, HttpServletResponse response) throws Exception {
        JobServletBase jobServlet = new JobServletBase(getCAEngine());
        jobServlet.get(request, response);
    }

    @Override
    @SupportedPath(method = HttpMethod.POST, paths = {"/{}/start"})
    public void post(HttpServletRequest request, HttpServletResponse response) throws Exception {
        JobServletBase jobServlet = new JobServletBase(getCAEngine());
        jobServlet.post(request, response);
    }
}
