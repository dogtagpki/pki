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
import com.netscape.management.client.*;
import com.netscape.management.client.console.*;
import com.netscape.management.client.util.*;
import com.netscape.management.client.topology.ug.*;
import netscape.ldap.*;

/**
 * Initializes the framework with topology information
 */
public class TopologyInitializer extends FrameworkInitializer {
    public static String PERMID_UGTAB = "UGTabVisibility";
    public static String PERMID_UGEDIT = "UGEditing";
    public static String PERMID_TOPOEDIT = "TopologyEditing";
    public static String PERMID_SECURITY = "SecurityVisibility";
    public static String PERMID_CUSTOMVIEW = "CustomViewEditing";

    private static boolean canEditTopology = true;
    
    public static ResourceSet _resource = new ResourceSet("com.netscape.management.client.topology.topology");
    private ConsoleInfo consoleInfo;
    private static Hashtable topologyPlugin;
    private UIPermissions uip = null;

    private static String getPermString(String id) {
        return _resource.getString("Permissions", id);
    }
    
    /**
     * constructor
     *
     * @param info	global information object
     */
    public TopologyInitializer(ConsoleInfo info) {
        super();

        consoleInfo = info;

        setFrameTitle(new ResourceSet("com.netscape.management.client.theme.theme").getString("console", "title"));  // not localized because it is product name
        setMinimizedImage( new RemoteImage("com/netscape/management/client/theme/images/logo16.gif").getImage());
        setBannerImage( new RemoteImage("com/netscape/management/client/theme/images/ConsoleBanner.gif").getImage());

        uip = new UIPermissions(LDAPUtil.getAdminGlobalParameterEntry());
        uip.addPermission(PERMID_UGTAB, getPermString("UGTabName"), getPermString("UGTabDesc"));
        uip.addPermission(PERMID_UGEDIT, getPermString("UGEditName"), getPermString("UGEditDesc"));
        uip.addPermission(PERMID_TOPOEDIT, getPermString("TPEditName"), getPermString("TPEditDesc"));
        uip.addPermission(PERMID_SECURITY, getPermString("SecurityName"), getPermString("SecurityDesc"));
        uip.addPermission(PERMID_CUSTOMVIEW, getPermString("CustomViewName"), getPermString("CustomViewDesc"));
        this.setUIPermissions(uip);
        
        canEditTopology = uip.hasPermission(PERMID_TOPOEDIT);
        
        setupTopologyPage();
        setupUserPage();
    }

    public static boolean canEditTopology()
    {
        return canEditTopology;
    }
    
    /**
      * setup the user page
      */
    private void setupUserPage() {
        // need to find out the user base DN, DS Host and port number
        if(uip.hasPermission(PERMID_UGTAB))
            addPage(new UGPage(consoleInfo, uip.hasPermission(PERMID_UGEDIT)));
    }

    /**
      * setup the topology page
      */
    private void setupTopologyPage() {
        getTopologyPluginFromDS(consoleInfo);
        TopologyModel defaultModel = new TopologyModel(consoleInfo, canEditTopology);
        ResourcePage topologyPage =
                new TopologyResourcePage(consoleInfo, defaultModel, uip.hasPermission(PERMID_CUSTOMVIEW));
        topologyPage.setPageTitle(_resource.getString("topology","title"));
        addPage(topologyPage);
    }

    /**
      * retrieve all the topology plugin information from the Directory server
      *
      * @param info global information block
      * @return Hashtable which contains all the topology plugin information
      */
    static public Hashtable getTopologyPluginFromDS(ConsoleInfo info) {
        String ldapLocation = "cn=topologyplugin,"+
                LDAPUtil.getAdminGlobalParameterEntry();
        topologyPlugin = new Hashtable();
        try {
            LDAPConnection ldc = info.getLDAPConnection();
            LDAPSearchResults results =
                    ldc.search(ldapLocation, LDAPConnection.SCOPE_ONE,
                    "objectclass=nstopologyplugin",null, false);
            while (results.hasMoreElements()) {
                LDAPEntry entry = (LDAPEntry) results.next();
                // get the topology plugin
                LDAPAttribute attribute = entry.getAttribute("nsclassname");

                if (attribute != null) {
                    Enumeration eAttributes = attribute.getStringValues();
                    while (eAttributes.hasMoreElements()) {
                        String sNetworkTopologyClass =
                                (String) eAttributes.nextElement();
                        Class c = ClassLoaderUtil.getClass(info,
                                sNetworkTopologyClass);

                        if (c != null) {
                            try {
                                ITopologyPlugin plugin =
                                        (ITopologyPlugin) c.newInstance();
                                plugin.initialize(info);
                                topologyPlugin.put(c.getName(), plugin);
                            } catch (Exception e) {
                                Debug.println("Cannot create: "+
                                        sNetworkTopologyClass);
                            }
                        }
                    }
                }
            }
        } catch (LDAPException e) {
            Debug.println("Cannot open: "+ldapLocation);
        }
        // if we could not find a topology plugin in the directory
        // server, just use the default one
        if (topologyPlugin.isEmpty()) {
        	String defaultname = "com.netscape.management.client.topology.DefaultTopologyPlugin";
        	Debug.println(5, "TopologyInitializer.getTopologyPluginFromDS: " +
        					 "could not find a topology plugin under " +
        					 ldapLocation +  ": using " + defaultname);
        	ITopologyPlugin plugin = new DefaultTopologyPlugin();
        	plugin.initialize(info);
        	topologyPlugin.put(defaultname, plugin);
        }
        return topologyPlugin;
    }

    /**
      * return the topology plugin hashtable
      *
      * @return hashtable which contains all the topology plugin
      */
    static public Hashtable getNetworkTopologyPlugin() {
        return topologyPlugin;
    }

    /**
      * set the topology plugin hashtable
      *
      * @param h hashtable which contain topology plugin.
      */
    static public void setNetworkTopologyPlugin(Hashtable h) {
        topologyPlugin = h;
    }
}
