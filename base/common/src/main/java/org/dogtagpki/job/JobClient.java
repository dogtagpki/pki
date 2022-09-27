//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.job;

import javax.ws.rs.core.Response;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;

/**
 * @author Endi S. Dewata
 */
public class JobClient extends Client {

    public static final Logger logger = LoggerFactory.getLogger(JobClient.class);

    JobResource resource;

    public JobClient(PKIClient client, String subsystem) throws Exception {
        super(client, subsystem, "config");
        init();
    }

    public void init() throws Exception {
        resource = createProxy(JobResource.class);
    }

    public JobCollection findJobs() throws Exception {
        Response response = resource.findJobs();
        return client.getEntity(response, JobCollection.class);
    }

    public JobInfo getJob(String id) throws Exception {
        Response response = resource.getJob(id);
        return client.getEntity(response, JobInfo.class);
    }

    public void startJob(String id) throws Exception {
        Response response = resource.startJob(id);
        client.getEntity(response, Void.class);
    }
}
