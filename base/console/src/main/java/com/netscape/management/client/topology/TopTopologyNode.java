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

import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import javax.swing.tree.MutableTreeNode;

import com.netscape.management.client.IResourceObject;
import com.netscape.management.client.console.Console;
import com.netscape.management.client.console.SplashScreen;
import com.netscape.management.client.util.Debug;


/**
 * Top Topology Node class
 */
public class TopTopologyNode extends ServerLocNode {
    /**
      * constructor for Top Topology node
      */
    public TopTopologyNode() {
        super(null);
    }

    /**
      * initialize the top topology node
      */
    public void reload() {
        super.reload();
        removeAllChildren();


        // Show status
        SplashScreen splashScreen = SplashScreen.getInstance();
        if (splashScreen != null && splashScreen.isVisible()) {
            splashScreen.setStatusText(
                    Console._resource.getString("splash", "discoveryOn"));

        }

        Hashtable hTopologyPlugins =
                TopologyInitializer.getNetworkTopologyPlugin();

        // add other plugin host
        /* this is for the top nodes */
        if (hTopologyPlugins != null) {
            Enumeration ePlugins = hTopologyPlugins.elements();
            while (ePlugins.hasMoreElements()) {
                ITopologyPlugin plugin =
                        (ITopologyPlugin) ePlugins.nextElement();
                Vector vHosts = plugin.getTopNodes();
                if (vHosts != null) {
                    Enumeration eHost = vHosts.elements();
                    while (eHost.hasMoreElements()) {
                        IResourceObject host =
                                (IResourceObject) eHost.nextElement();
                        if (host instanceof MutableTreeNode) {
                            add((MutableTreeNode) host);
                        } else {
                            Debug.println(host.getName() + " is not a MutableTreeNode .");
                        }
                    }
                }
            }
        }
    }
}
