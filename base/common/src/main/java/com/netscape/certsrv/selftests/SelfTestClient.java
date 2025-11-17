//--- BEGIN COPYRIGHT BLOCK ---
//This program is free software; you can redistribute it and/or modify
//it under the terms of the GNU General Public License as published by
//the Free Software Foundation; version 2 of the License.
//
//This program is distributed in the hope that it will be useful,
//but WITHOUT ANY WARRANTY; without even the implied warranty of
//MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//GNU General Public License for more details.
//
//You should have received a copy of the GNU General Public License along
//with this program; if not, write to the Free Software Foundation, Inc.,
//51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
//(C) 2013 Red Hat, Inc.
//All rights reserved.
//--- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.selftests;

import java.util.HashMap;
import java.util.Map;

import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.SubsystemClient;

/**
 * @author Endi S. Dewata
 */
public class SelfTestClient extends Client {

    public SelfTestClient(SubsystemClient subsystemClient) throws Exception {
        this(subsystemClient.client, subsystemClient.name);
    }

    public SelfTestClient(PKIClient client, String subsystem) throws Exception {
        super(client, subsystem, "selftests");
    }

    public SelfTestCollection findSelfTests(String filter, Integer start, Integer size) throws Exception {
        Map<String, Object> params = new HashMap<>();
        if (filter != null) params.put("filter", filter);
        if (start != null) params.put("start", start);
        if (size != null) params.put("size", size);
        return get(null, params, SelfTestCollection.class);
    }

    public void executeSelfTests(String action) throws Exception {
        Map<String, Object> params = new HashMap<>();
        if (action != null) params.put("action", action);
        post(null, params, Void.class);
    }

    public SelfTestResults runSelfTests() throws Exception {
        return post("run", SelfTestResults.class);
    }

    public SelfTestResult runSelfTest(String selfTestID) throws Exception {
        return post(selfTestID + "/run", SelfTestResult.class);
    }

    public SelfTestData getSelfTest(String selfTestID) throws Exception {
        return get(selfTestID, SelfTestData.class);
    }
}
