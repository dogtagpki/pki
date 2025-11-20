//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.job;

import org.apache.commons.cli.CommandLine;
import org.dogtagpki.cli.CLIException;
import org.dogtagpki.job.JobClient;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;

/**
 * @author Endi S. Dewata
 */
public class JobStartCLI extends SubsystemCommandCLI {

    public static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(JobStartCLI.class);

    JobCLI jobCLI;

    public JobStartCLI(JobCLI jobCLI) {
        super("start", "Start job", jobCLI);
        this.jobCLI = jobCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " <job ID>", options);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();
        if (cmdArgs.length == 0) {
            throw new CLIException("Missing job ID");
        }

        String id = cmdArgs[0];

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = mainCLI.getClient();
        JobClient jobClient = jobCLI.getJobClient(client);
        jobClient.startJob(id);
    }
}
