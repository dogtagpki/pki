//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.tps.rest.v2;

import java.io.PrintWriter;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.dogtagpki.job.JobCollection;
import org.dogtagpki.job.JobInfo;
import org.dogtagpki.server.rest.v2.JobServletBase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.WebAction;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
@WebServlet(
        name = "tpsJobs",
        urlPatterns = "/v2/jobs/*")
public class JobServlet extends TPSServlet {
    private static final long serialVersionUID = 1L;
    public static final Logger logger = LoggerFactory.getLogger(JobServlet.class);

    @WebAction(method = HttpMethod.GET, paths = { "/"})
    public void getJobs(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("JobServlet.getJobs(): session: {}", session.getId());
        PrintWriter out = response.getWriter();
        JobServletBase jobServlet = new JobServletBase(getTPSEngine());
        JobCollection jobs = jobServlet.findJobs(request.getUserPrincipal());
        out.println(jobs.toJSON());
    }

    @WebAction(method = HttpMethod.GET, paths = { "/{}"})
    public void getJob(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("JobServlet.getJob(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String jobId = pathElement[0];
        JobServletBase jobServlet = new JobServletBase(getTPSEngine());
        JobInfo job = jobServlet.getJob(jobId, request.getUserPrincipal());
        PrintWriter out = response.getWriter();
        out.println(job.toJSON());
    }

    @WebAction(method = HttpMethod.POST, paths = {"/{}/start"})
    public void postJobStart(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("JobServlet.postJobStart(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String jobId = pathElement[0];
        JobServletBase jobServlet = new JobServletBase(getTPSEngine());
        jobServlet.startJob(jobId, request.getUserPrincipal());
    }
}
