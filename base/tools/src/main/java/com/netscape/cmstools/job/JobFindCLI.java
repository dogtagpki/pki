//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.job;

import java.util.Collection;

import org.apache.commons.cli.CommandLine;
import org.dogtagpki.cli.CommandCLI;
import org.dogtagpki.job.JobClient;
import org.dogtagpki.job.JobCollection;
import org.dogtagpki.job.JobInfo;

import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class JobFindCLI extends CommandCLI {

    public static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(JobFindCLI.class);

    JobCLI jobCLI;

    public JobFindCLI(JobCLI jobCLI) {
        super("find", "Find jobs", jobCLI);
        this.jobCLI = jobCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName(), options);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        JobClient jobClient = jobCLI.getJobClient();
        JobCollection response = jobClient.findJobs();

        Collection<JobInfo> entries = response.getEntries();
        boolean first = true;

        for (JobInfo jobData : entries) {

            if (first) {
                first = false;
            } else {
                System.out.println();
            }

            JobCLI.printJob(jobData);
        }
    }
}
