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

import java.util.*;
import com.netscape.management.client.console.*;
import com.netscape.management.client.*;
import com.netscape.management.client.util.*;
import netscape.ldap.*;

/**
	* Allows customization of topology tree data.
	*/
public class DefaultTopologyPlugin implements ITopologyPlugin {
    static public String name = "com.netscape.management.client.topology.DefaultTopologyPlugin";
    private static ResourceSet _resource = new ResourceSet("com.netscape.management.client.topology.topology");

    protected ServiceLocator _sl;
    protected ConsoleInfo _info;

    /**
     * initialize the plugin object
     *
     * @param info global info
     */
    public void initialize(ConsoleInfo info) {
        _sl = new ServiceLocator(info);
        _info = info;
    }

    /**
      * return a list of top level object which implements IResourceObject and
      * MutableTreeNode interface.
      *
      * @return list of the top nodes
      */
    public Vector getTopNodes() {
        // reload
        Vector v = new Vector();

        LDAPSearchResults result = (LDAPSearchResults)_sl.getDomains();
        if (result != null) {
            while (result.hasMoreElements()) {
                LDAPEntry entry = null;
                try {
                    entry = (LDAPEntry) result.next();
                } catch (Exception e) {
                    // ldap exception
                    continue;
                }
                DomainNode dn = new DomainNode(_sl, entry);
                //if(searchChildByName(dn.getName())==null)
                //{
                v.addElement(dn);
                dn.reload();
                //}
            }
        }
        return v;
    }

    /**
      * return a list of product for the specified tree node. The return vector is a list of object which implements
      * IResourceObject and MutableTreeNode interface.
      *
      * @param obj parent resource object
      * @return a vector lists of additional resource object
      */
    public Vector getAdditionalChildren(ResourceObject obj) {
        return null;
    }

    /**
      * get the node id for the specified resource object
      *
      * @param res resource object node
      * @return ID of the given resource object
      */
    public String getIDByResourceObject(ResourceObject res) {
        String sReturn = null;

        if ((res instanceof HostNode) || (res instanceof AdminGroupNode) ||
                (res instanceof DomainNode) ||
                (res instanceof ServerNode)) {
            ServerLocNode node = (ServerLocNode) res;
            sReturn = node.getDN();
        }

        return sReturn;
    }
    
    /**
     * get resource object by the given ID
     *
     * @param id ID of the required object
     * @return resource object of the ID
     */
    public ResourceObject getResourceObjectByID(String id) {
        Debug.println(6, "DefaultTopologyPlugin.getResourceObjectByID: id=" + id);
        ResourceObject rReturn = null;
        try {
            LDAPConnection ldc = _info.getLDAPConnection();
            LDAPEntry entry = ldc.read(id);
            if (entry != null) {
                StringTokenizer st = new StringTokenizer(id, ",");
                if (st.countTokens() == 2) {
                    // it is XXX,o=netscaperoot
                    // so it is a domain
                    rReturn = new DomainNode(_sl, entry);
                } else {
                    LDAPAttribute attr = entry.getAttribute("objectclass");
                    Enumeration eObjectClass = attr.getStringValues();
                    while (eObjectClass.hasMoreElements()) {
                        String sObjectClass =
                                (String) eObjectClass.nextElement();
                        if (sObjectClass.equalsIgnoreCase("nsHost")) {
                            LDAPAttribute nameAttr =
                                    entry.getAttribute("serverhostname");
                            String name = (nameAttr == null) ?
                                    _resource.getString("General",
                                    "noname") : LDAPUtil.flatting(nameAttr);
                            rReturn = new HostNode(_sl, id, name);
                            break;
                        } else if (sObjectClass.equalsIgnoreCase("nsAdminDomain")) {
                            rReturn = new DomainNode(_sl, entry);
                            break;
                        } else if (sObjectClass.equalsIgnoreCase("nsAdminGroup")) {
                            rReturn = new AdminGroupNode(_sl, entry);
                            break;
                        } else if (sObjectClass.equalsIgnoreCase("netscapeServer")) {
                            rReturn = new ServerNode(_sl, entry);
                            break;
                        }
                    }
                }
            } else {
                Debug.println("getResourceObjectByID() cannot find = " + id);
            }
        } catch (LDAPException e) {
            Debug.println("DefaultTopologyPlugin: cannot create node for: "+id);
            Debug.println(" because " + e);
        }
        return rReturn;
    }
}

