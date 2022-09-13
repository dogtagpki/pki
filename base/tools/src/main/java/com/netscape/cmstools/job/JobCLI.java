//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.job;

import org.dogtagpki.cli.CLI;
import org.dogtagpki.job.JobClient;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.cmstools.cli.SubsystemCLI;

/**
 * @author Endi S. Dewata
 */
public class JobCLI extends CLI {

    JobClient jobClient;

    public JobCLI(SubsystemCLI parent) {
        super("job", "Job management commands", parent);

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
}
