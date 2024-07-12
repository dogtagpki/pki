//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.rest.v2;

import java.io.PrintWriter;
import java.security.Principal;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.dogtagpki.job.JobCollection;
import org.dogtagpki.job.JobInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.ForbiddenException;
import com.netscape.certsrv.base.ResourceNotFoundException;
import com.netscape.cms.realm.PKIPrincipal;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.jobs.JobConfig;
import com.netscape.cmscore.jobs.JobsConfig;
import com.netscape.cmscore.jobs.JobsScheduler;
import com.netscape.cmscore.jobs.JobsSchedulerConfig;

/**
 * @author Marco Fargetta {@literal <mfargett@redhat.com>}
 * @author Endi S. Dewata
 */
public class JobServletBase {
    public static final Logger logger = LoggerFactory.getLogger(JobServletBase.class);

    private CMSEngine engine;

    public JobServletBase(CMSEngine engine) {
        this.engine = engine;
    }

    public void get(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("JobServletBase.get(): session: {}", session.getId());

        PrintWriter out = response.getWriter();
        if (request.getPathInfo() == null) {
            JobCollection jobs = findJobs(request.getUserPrincipal());
            out.println(jobs.toJSON());
            return;
        }
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        if (pathElement.length == 1) {
            String jobId = pathElement[0];
            JobInfo job = getJob(jobId, request.getUserPrincipal());
            out.println(job.toJSON());
            return;
        }
        response.setStatus(HttpServletResponse.SC_NOT_FOUND);
    }

    public void post(HttpServletRequest request, HttpServletResponse response) throws Exception {
        HttpSession session = request.getSession();
        logger.debug("SelfTestServletBase.post(): session: {}", session.getId());

        if (request.getPathInfo() == null) {
            response.setStatus(HttpServletResponse.SC_NOT_FOUND);
            return;
        }
        String[] pathElement = request.getPathInfo().substring(1).split("/");
        if (pathElement.length == 2 && pathElement[1].equals("start")) {
            String jobId = pathElement[0];
            startJob(jobId, request.getUserPrincipal());
            return;
        }
        response.setStatus(HttpServletResponse.SC_NOT_FOUND);
    }

    private JobCollection findJobs(Principal principal) throws EBaseException {

        logger.info("JobServletBase: Finding jobs");

        JobCollection jobs = new JobCollection();

        EngineConfig engineConfig = engine.getConfig();
        JobsSchedulerConfig jobsSchedulerConfig = engineConfig.getJobsSchedulerConfig();
        JobsConfig jobsConfig = jobsSchedulerConfig.getJobsConfig();

        logger.info("JobServletBase: - principal: {}", principal);

        boolean isAdmin = isAdmin(principal);

        logger.info("JobServletBase: - jobs:");
        Enumeration<String> list = jobsConfig.getSubStoreNames().elements();
        while (list.hasMoreElements()) {
            String id = list.nextElement();
            logger.info("JobServletBase:   - {}", id);

            JobConfig jobConfig = jobsConfig.getJobConfig(id);

            boolean isOwner = isOwner(principal, jobConfig);
            if (!isAdmin && !isOwner) {
                continue;
            }

            JobInfo jobInfo = createJobInfo(id, jobConfig, false);
            jobs.addEntry(jobInfo);
        }

        return jobs;
    }

    public JobInfo getJob(String id, Principal principal) throws EBaseException {

        logger.info("JobServletBase: Getting job {}", id);

        EngineConfig engineConfig = engine.getConfig();
        JobsSchedulerConfig jobsSchedulerConfig = engineConfig.getJobsSchedulerConfig();
        JobsConfig jobsConfig = jobsSchedulerConfig.getJobsConfig();

        JobConfig jobConfig = jobsConfig.getJobConfig(id);

        if (jobConfig == null) {
            throw new ResourceNotFoundException("Job " + id + " not found");
        }

        logger.info("JobServletBase: - principal: {}", principal);

        boolean isAdmin = isAdmin(principal);
        boolean isOwner = isOwner(principal, jobConfig);

        if (!isAdmin && !isOwner) {
            String principalName = principal == null ? "unknown" : principal.getName();
            throw new ForbiddenException("User '" + principalName + "' not allow to access job " + id);
        }

        return createJobInfo(id, jobConfig, true);
    }

    private void startJob(String id, Principal principal) throws EBaseException {

        logger.info("JobServletBase: Starting job {}", id);

        EngineConfig engineConfig = engine.getConfig();
        JobsSchedulerConfig jobsSchedulerConfig = engineConfig.getJobsSchedulerConfig();
        JobsConfig jobsConfig = jobsSchedulerConfig.getJobsConfig();

        JobConfig jobConfig = jobsConfig.getJobConfig(id);

        if (jobConfig == null) {
            throw new ResourceNotFoundException("Job " + id + " not found");
        }

        logger.info("JobServletBase: - principal: {}", principal);

        boolean isAdmin = isAdmin(principal);
        boolean isOwner = isOwner(principal, jobConfig);

        if (!isAdmin && !isOwner) {
            throw new ForbiddenException("User " + principal.getName() + " not allow to start job " + id);
        }

        JobsScheduler jobsScheduler = engine.getJobsScheduler();
        jobsScheduler.startJob(id);
    }

    private boolean isAdmin(Principal principal) {

        if (principal instanceof PKIPrincipal pkiPrincipal) {
            List<String> roles = Arrays.asList(pkiPrincipal.getRoles());
            return roles.contains("Administrators");
        }

        return false;
    }

    private boolean isOwner(Principal principal, JobConfig jobConfig) throws EBaseException {

        if (principal == null) {
            return false;
        }

        String username = principal.getName();
        String owner = jobConfig.getOwner(); // can be null

        return username.equals(owner);
    }

    private JobInfo createJobInfo(String id, JobConfig jobConfig, boolean includeDetails) throws EBaseException {

        JobInfo jobInfo = new JobInfo();
        jobInfo.setID(id);

        // store the following config params as fields
        jobInfo.setEnabled(jobConfig.isEnabled());
        jobInfo.setCron(jobConfig.getCron());
        jobInfo.setPluginName(jobConfig.getPluginName());
        jobInfo.setOwner(jobConfig.getOwner());

        if (!includeDetails) {
            return jobInfo;
        }

        // store the remaining config params
        Map<String, String> properties = jobConfig.getProperties();
        for (String name : properties.keySet()) {

            if (name.equals("enabled")) continue;
            if (name.equals("cron")) continue;
            if (name.equals("pluginName")) continue;

            String value = properties.get(name);
            jobInfo.setParameter(name, value);
        }

        return jobInfo;
    }
}
