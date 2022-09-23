//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.server.rest;

import javax.ws.rs.core.Response;

import org.dogtagpki.job.JobResource;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.cms.servlet.base.SubsystemService;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.jobs.JobsScheduler;

/**
 * @author Endi S. Dewata
 */
public class JobService extends SubsystemService implements JobResource {

    public static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(JobService.class);

    @Override
    public Response startJob(String id) throws EBaseException {

        logger.info("JobService: Starting job " + id);

        CMSEngine engine = CMS.getCMSEngine();
        JobsScheduler jobsScheduler = engine.getJobsScheduler();
        jobsScheduler.startJob(id);

        return createOKResponse();
    }
}
