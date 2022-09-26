//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.job;

import org.dogtagpki.cli.CLI;
import org.dogtagpki.job.JobClient;
import org.dogtagpki.job.JobInfo;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.cmstools.cli.SubsystemCLI;

/**
 * @author Endi S. Dewata
 */
public class JobCLI extends CLI {

    JobClient jobClient;

    public JobCLI(SubsystemCLI parent) {
        super("job", "Job management commands", parent);

        addModule(new JobFindCLI(this));
        addModule(new JobStartCLI(this));
    }

    public JobClient getJobClient() throws Exception {

        if (jobClient != null) return jobClient;

        SubsystemCLI subsystemCLI = (SubsystemCLI) parent;
        String subsystem = subsystemCLI.getName();

        PKIClient client = getClient();
        jobClient = new JobClient(client, subsystem);

        return jobClient;
    }

    public static void printJob(JobInfo jobData) {
        System.out.println("  Job ID: " + jobData.getID());
        System.out.println("  Enabled: " + jobData.isEnabled());

        String cron = jobData.getCron();
        if (cron != null) {
            System.out.println("  Cron: " + cron);
        }

        System.out.println("  Plugin: " + jobData.getPluginName());
    }
}
