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
//(C) 2015 Red Hat, Inc.
//All rights reserved.
//--- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.system;

import java.util.Collection;

import com.netscape.certsrv.client.Client;
import com.netscape.certsrv.client.PKIClient;

/**
* @author Ade Lee &lt;alee@redhat.com&gt;
*/
public class FeatureClient extends Client {

    public FeatureClient(PKIClient client, String subsystem) throws Exception {
        super(client, subsystem, "config/features");
    }

    public Collection<Feature> listFeatures() throws Exception {
        return getCollection(null, null, Feature.class);
    }

    public Feature getFeature(String featureID) throws Exception {
        return get(featureID, null, Feature.class);
    }
}
