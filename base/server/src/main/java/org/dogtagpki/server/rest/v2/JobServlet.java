//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.rest.v2;

import java.io.PrintWriter;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

import org.dogtagpki.job.JobCollection;
import org.dogtagpki.job.JobInfo;
import org.dogtagpki.server.rest.base.JobServletBase;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.WebAction;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 */
public class JobServlet extends PKIServlet {
    private static final long serialVersionUID = 1L;
    public static final Logger logger = LoggerFactory.getLogger(JobServlet.class);

    private JobServletBase jobServletBase;

    @Override
    public void init() throws ServletException {
        super.init();
        jobServletBase = new JobServletBase(getEngine());
    }

    @WebAction(method = HttpMethod.GET, paths = {""})
    public void getJobs(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("JobServlet.getJobs(): session: {}", session.getId());
        PrintWriter out = response.getWriter();
        JobCollection jobs = jobServletBase.findJobs(request.getUserPrincipal());
        out.println(jobs.toJSON());
    }

    @WebAction(method = HttpMethod.GET, paths = {"{}"})
    public void getJob(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("JobServlet.getJob(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String jobId = pathElement[0];
        JobInfo job = jobServletBase.getJob(jobId, request.getUserPrincipal());
        PrintWriter out = response.getWriter();
        out.println(job.toJSON());
    }

    @WebAction(method = HttpMethod.POST, paths = {"{}/start"})
    public void postJobStart(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("JobServlet.postJobStart(): session: {}", session.getId());
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        String jobId = pathElement[0];
        jobServletBase.startJob(jobId, request.getUserPrincipal());
    }
}
