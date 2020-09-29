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
package com.netscape.certsrv.logging;

import javax.ws.rs.core.Response;

import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;

/**
 * @author Endi S. Dewata
 */
public class ActivityClient extends Client {

    public ActivityResource resource;

    public ActivityClient(PKIClient client, String subsystem) throws Exception {
        super(client, subsystem, "activity");
        init();
    }

    public void init() throws Exception {
        resource = createProxy(ActivityResource.class);
    }

    public ActivityCollection findActivities(String filter, Integer start, Integer size) throws Exception {
        Response response = resource.findActivities(filter, start, size);
        return client.getEntity(response, ActivityCollection.class);
    }

    public ActivityData getActivity(String activityID) throws Exception {
        Response response = resource.getActivity(activityID);
        return client.getEntity(response, ActivityData.class);
    }
}
