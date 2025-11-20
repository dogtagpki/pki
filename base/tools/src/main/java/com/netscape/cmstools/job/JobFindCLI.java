//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.job;

import java.util.Collection;

import org.apache.commons.cli.CommandLine;
import org.dogtagpki.job.JobClient;
import org.dogtagpki.job.JobCollection;
import org.dogtagpki.job.JobInfo;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;

/**
 * @author Endi S. Dewata
 */
public class JobFindCLI extends SubsystemCommandCLI {

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

        PKIClient client = mainCLI.getClient();
        JobClient jobClient = jobCLI.getJobClient(client);
        JobCollection response = jobClient.findJobs();

        Collection<JobInfo> entries = response.getEntries();
        boolean first = true;

        for (JobInfo jobInfo : entries) {

            if (first) {
                first = false;
            } else {
                System.out.println();
            }

            JobCLI.printJob(jobInfo);
        }
    }
}
