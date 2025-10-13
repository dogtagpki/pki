//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.rest.v1;

import java.security.Principal;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;

import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.core.Response;

import org.dogtagpki.job.JobCollection;
import org.dogtagpki.job.JobInfo;
import org.dogtagpki.job.JobResource;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.ResourceNotFoundException;
import com.netscape.cms.realm.PKIPrincipal;
import com.netscape.cms.servlet.base.SubsystemService;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.jobs.JobConfig;
import com.netscape.cmscore.jobs.JobsConfig;
import com.netscape.cmscore.jobs.JobsScheduler;
import com.netscape.cmscore.jobs.JobsSchedulerConfig;

/**
 * @author Endi S. Dewata
 */
public class JobService extends SubsystemService implements JobResource {

    public static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(JobService.class);

    boolean isAdmin(Principal principal) {

        if (principal instanceof PKIPrincipal pkiPrincipal) {
            List<String> roles = Arrays.asList(pkiPrincipal.getRoles());
            return roles.contains("Administrators");
        }

        return false;
    }

    boolean isOwner(Principal principal, JobConfig jobConfig) throws EBaseException {

        if (principal == null) {
            return false;
        }

        String username = principal.getName();
        String owner = jobConfig.getOwner(); // can be null

        return username.equals(owner);
    }

    public JobInfo createJobInfo(String id, JobConfig jobConfig, boolean includeDetails) throws EBaseException {

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

    @Override
    public Response findJobs() throws EBaseException {

        logger.info("JobService: Finding jobs");

        JobCollection response = new JobCollection();

        CMSEngine engine = getCMSEngine();
        EngineConfig engineConfig = engine.getConfig();
        JobsSchedulerConfig jobsSchedulerConfig = engineConfig.getJobsSchedulerConfig();
        JobsConfig jobsConfig = jobsSchedulerConfig.getJobsConfig();

        Principal principal = servletRequest.getUserPrincipal();
        logger.info("JobService: - principal: " + principal);

        boolean isAdmin = isAdmin(principal);

        logger.info("JobService: - jobs:");
        Enumeration<String> list = jobsConfig.getSubStoreNames().elements();
        while (list.hasMoreElements()) {
            String id = list.nextElement();
            logger.info("JobService:   - " + id);

            JobConfig jobConfig = jobsConfig.getJobConfig(id);

            boolean isOwner = isOwner(principal, jobConfig);
            if (!isAdmin && !isOwner) {
                continue;
            }

            JobInfo jobInfo = createJobInfo(id, jobConfig, false);
            response.addEntry(jobInfo);
        }

        return createOKResponse(response);
    }

    @Override
    public Response getJob(String id) throws EBaseException {

        logger.info("JobService: Getting job " + id);

        CMSEngine engine = getCMSEngine();
        EngineConfig engineConfig = engine.getConfig();
        JobsSchedulerConfig jobsSchedulerConfig = engineConfig.getJobsSchedulerConfig();
        JobsConfig jobsConfig = jobsSchedulerConfig.getJobsConfig();

        JobConfig jobConfig = jobsConfig.getJobConfig(id);

        if (jobConfig == null) {
            throw new ResourceNotFoundException("Job " + id + " not found");
        }

        Principal principal = servletRequest.getUserPrincipal();
        logger.info("JobService: - principal: " + principal);

        boolean isAdmin = isAdmin(principal);
        boolean isOwner = isOwner(principal, jobConfig);

        if (!isAdmin && !isOwner) {
            throw new ForbiddenException();
        }

        JobInfo jobInfo = createJobInfo(id, jobConfig, true);

        return createOKResponse(jobInfo);
    }

    @Override
    public Response startJob(String id) throws EBaseException {

        logger.info("JobService: Starting job " + id);

        CMSEngine engine = getCMSEngine();
        EngineConfig engineConfig = engine.getConfig();
        JobsSchedulerConfig jobsSchedulerConfig = engineConfig.getJobsSchedulerConfig();
        JobsConfig jobsConfig = jobsSchedulerConfig.getJobsConfig();

        JobConfig jobConfig = jobsConfig.getJobConfig(id);

        if (jobConfig == null) {
            throw new ResourceNotFoundException("Job " + id + " not found");
        }

        Principal principal = servletRequest.getUserPrincipal();
        logger.info("JobService: - principal: " + principal);

        boolean isAdmin = isAdmin(principal);
        boolean isOwner = isOwner(principal, jobConfig);

        if (!isAdmin && !isOwner) {
            throw new ForbiddenException();
        }

        JobsScheduler jobsScheduler = engine.getJobsScheduler();
        jobsScheduler.startJob(id);

        return createOKResponse();
    }
}
