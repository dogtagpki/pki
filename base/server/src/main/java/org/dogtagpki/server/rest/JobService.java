//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.rest;

import java.util.Enumeration;

import javax.ws.rs.core.Response;

import org.dogtagpki.job.JobCollection;
import org.dogtagpki.job.JobInfo;
import org.dogtagpki.job.JobResource;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cms.servlet.base.SubsystemService;
import com.netscape.cmscore.apps.CMS;
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

    public JobInfo createJobData(String id, JobConfig jobConfig) throws EBaseException {

        JobInfo jobData = new JobInfo();
        jobData.setID(id);
        jobData.setEnabled(jobConfig.isEnabled());
        jobData.setCron(jobConfig.getCron());
        jobData.setPluginName(jobConfig.getPluginName());

        return jobData;
    }

    @Override
    public Response findJobs() throws EBaseException {

        logger.info("JobService: Finding jobs");

        JobCollection response = new JobCollection();

        CMSEngine engine = CMS.getCMSEngine();
        EngineConfig engineConfig = engine.getConfig();
        JobsSchedulerConfig jobsSchedulerConfig = engineConfig.getJobsSchedulerConfig();
        JobsConfig jobsConfig = jobsSchedulerConfig.getJobsConfig();

        Enumeration<String> list = jobsConfig.getSubStoreNames();
        while (list.hasMoreElements()) {
            String id = list.nextElement();
            logger.info("JobService: - " + id);

            JobConfig jobConfig = jobsConfig.getJobConfig(id);
            JobInfo jobData = createJobData(id, jobConfig);
            response.addEntry(jobData);
        }

        return createOKResponse(response);
    }

    @Override
    public Response startJob(String id) throws EBaseException {

        logger.info("JobService: Starting job " + id);

        CMSEngine engine = CMS.getCMSEngine();
        JobsScheduler jobsScheduler = engine.getJobsScheduler();
        jobsScheduler.startJob(id);

        return createOKResponse();
    }
}
