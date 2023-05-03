//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.job;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;

/**
 * @author Endi S. Dewata
 */
public class JobClient extends Client {

    public static final Logger logger = LoggerFactory.getLogger(JobClient.class);

    public JobClient(PKIClient client, String subsystem) throws Exception {
        super(client, subsystem, "jobs");
    }

    public JobCollection findJobs() throws Exception {
        return get(JobCollection.class);
    }

    public JobInfo getJob(String id) throws Exception {
        return get(id, JobInfo.class);
    }

    public void startJob(String id) throws Exception {
        post(id + "/start", Void.class);
    }
}
