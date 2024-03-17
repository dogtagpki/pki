/** BEGIN COPYRIGHT BLOCK
 * Copyright (C) 2001 Sun Microsystems, Inc.  Used by permission.
 * Copyright (C) 2005 Red Hat, Inc.
 * All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation version
 * 2.1 of the License.
 *                                                                                 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *                                                                                 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 * END COPYRIGHT BLOCK **/
package com.netscape.management.client.topology;

import com.netscape.management.client.util.*;
import netscape.ldap.*;

public class NetworkNode extends ServerLocNode {
    public static String _imageSource = "com/netscape/management/client/topology/images/";

    public NetworkNode(ServiceLocator sl) {
        super(sl);
        setName(TopologyInitializer._resource.getString("tree","network"));
        setIcon(new RemoteImage(_imageSource + "topnode.gif"));
    }

    /**
      * initialize the top toplogy node
      */
    public void reload() {
        super.reload();

        removeAllChildren();
        LDAPSearchResults result =
                (LDAPSearchResults) getServiceLocator().getDomains();
        Debug.println("after get result:");
        Object o = null;
        LDAPEntry entry = null;
        DomainNode dn = null;
        while (result.hasMoreElements()) {
            Debug.println("inside result:");
            o = result.nextElement();
            if ((o instanceof LDAPEntry) == false) {
                continue;
            }

            entry = (LDAPEntry) o;
            dn = new DomainNode(getServiceLocator(), entry);
            Debug.println("adding :"+dn.getName());
            if (searchChildByName(dn.getName()) == null) {
                add(dn);
                dn.reload();
            }
        }
    }
}
