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
import java.awt.*;
import javax.swing.event.*;
import javax.swing.tree.*;
import com.netscape.management.client.*;
import com.netscape.management.client.util.*;
import netscape.ldap.*;

/**
 * Machine (host) tree node in the topology view.
 */
public class HostNode extends ServerLocNode implements INodeInfo {
    public static ResourceSet resource = new ResourceSet("com.netscape.management.client.topology.topology");

    protected NodeData _nodeData[], _nameNodeData;
    protected NodeDataPanel _nodeDataPanel;
    protected IPage _viewInstance;

    private static RemoteImage _icon =
            new RemoteImage(resource.getString("tree","hostIcon"));
    private boolean isInitialized = false;
    private Vector _changeListeners = new Vector();

    String _os = "";
    String _platform = "";
    String _host = "";
    String _description = "";
    String _location = "";

    /**
     * constructor for the host node.
     *
     * @param sl service locator object
     * @param ldapEntry ldap entry for the host
     */
    public HostNode(ServiceLocator sl, LDAPEntry ldapEntry) {
        super(sl);
        initialize(ldapEntry);
    }


    /**
      * More efficient constructor. Load ldapEntry only if node is selected
      */
    public HostNode(ServiceLocator sl, String ldapDN, String host) {
        super(sl);
        setDN(ldapDN);
        setName(_host = host);
        setIcon(_icon);
    }


    /**
      *  initialize using stored DN
      *
      * @param ldapEntry ldap entry.
      */
    private void initialize() {
        try {
            initialize(_sl.getConnection().read(getDN()));
        } catch (Exception e) {
            Debug.println("HostNode.initialize() failed");
        }
    }

    /**
      *	get the ldap entry attributes and setup internal vraiable
      *
      * @param ldapEntry ldap entry.
      */
    private void initialize(LDAPEntry ldapEntry) {
        if (isInitialized)
            return;

        isInitialized = true;

        setDN(ldapEntry.getDN());

        // BUGBUG: need to get the images
        setIcon(_icon);

        if (ldapEntry != null) {
            LDAPAttributeSet findAttrs = ldapEntry.getAttributeSet();
            Enumeration enumAttrs = findAttrs.getAttributes();

            // get the important attributes from the server entry
            while (enumAttrs.hasMoreElements()) {
                LDAPAttribute anAttr =
                        (LDAPAttribute) enumAttrs.nextElement();
                String attrName = anAttr.getName();
                if (attrName.equalsIgnoreCase("serverHostName")) {
                    _host = LDAPUtil.flatting(anAttr.getStringValues());
                    setName(_host);
                } else if (attrName.equalsIgnoreCase("description")) {
                    _description =
                            LDAPUtil.flatting(anAttr.getStringValues());
                } else if (attrName.equalsIgnoreCase("nsHostLocation")) {
                    _location = LDAPUtil.flatting(anAttr.getStringValues());
                } else if (attrName.equalsIgnoreCase("nshardwareplatform")) {
                    _platform = LDAPUtil.flatting(anAttr.getStringValues());
                } else if (attrName.equalsIgnoreCase("nsosVersion")) {
                    _os = LDAPUtil.flatting(anAttr.getStringValues());
                }
            }

            _nodeData = new NodeData[]{ _nameNodeData =
                    new NodeData("serverHostName",
                    _resource.getString("ServerObject",
                    "serverHostName"), getName(), true, true),
            new NodeData("description",
                    _resource.getString("ServerObject","description"),
                    _description, true),
            new NodeData("nsHostLocation",
                    _resource.getString("HostInfoPanel","location"),
                    _location, true),
            new NodeData("platform",
                    _resource.getString("HostInfoPanel","platform"),
                    _platform, false),
            new NodeData("os",
                    _resource.getString("HostInfoPanel","system"),
                    _os, false), };
        }
    }

    /**
      * reload the information by populate the tree with Admin Group information
      */
    public void reload() {
        if (!isInitialized)
            initialize();

        // get the children information
        removeAllChildren();
        super.reload();
        LDAPSearchResults result =
                (LDAPSearchResults) getServiceLocator().getAdminGroup(
                getDN());
        if (result != null) {
            try {
                while (result.hasMoreElements()) {
                    LDAPEntry findEntry = (LDAPEntry) result.next();
                    AdminGroupNode agn = new AdminGroupNode(_sl, findEntry);
                    agn.setAdminOS(_os);
                    if (searchChildByName(agn.getName()) == null)
                        add(agn);
                }
            } catch (Exception e) {
                // ldap exception
            }
        }

        // add other plugin host
        Hashtable hTopologyPlugins =
                TopologyInitializer.getNetworkTopologyPlugin();
        if (hTopologyPlugins != null) {
            Enumeration ePlugins = hTopologyPlugins.keys();
            while (ePlugins.hasMoreElements()) {
                String sKeyName = (String) ePlugins.nextElement();
                if (!sKeyName.equals(DefaultTopologyPlugin.name)) {
                    ITopologyPlugin plugin =
                            (ITopologyPlugin) hTopologyPlugins.get(
                            sKeyName);
                    Vector vProducts = plugin.getAdditionalChildren(
                            (ResourceObject) this);
                    if (vProducts != null) {
                        Enumeration eProducts = vProducts.elements();
                        while (eProducts.hasMoreElements()) {
                            IResourceObject product = (IResourceObject)
                                    eProducts.nextElement();
                            if (searchChildByName(product.getName()) ==
                                    null) {
                                if (product instanceof MutableTreeNode) {
                                    add((MutableTreeNode) product);
                                } else {
                                    Debug.println(product.getName() + " is not a MutableTreeNode .");
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /**
      * get the configuration panel
      *
      * @return configuration panel
      */
    public Component getCustomPanel() {
        _nodeDataPanel = new NodeDataPanel(getIcon(), getName(), this);
		_nodeDataPanel.setHelpTopic("admin", "topology-hostnode");
        return _nodeDataPanel;
    }


    /**
      * Uselect the node (override method)
      *
      * For the immediate garbage collection release the reference to nodeDataPanel
      *
      * @param viewInstance current Page
      */
    public void unselect(IPage viewInstance) {
        _nodeDataPanel = null;
    }

    /**
      * select the node (override method)
      *
      * @param viewInstance current Page
      */
    public void select(IPage viewInstance) {
        _viewInstance = viewInstance;
    }

    /**
      * Number of entries for this node.
      * Implements INodeInfo
      */
    public int getNodeDataCount() {
        initialize();
        return _nodeData.length;
    }


    /**
      * Return node entry at specified index.
      * Implements INodeInfo
      */
    public NodeData getNodeData(int index) {
        return _nodeData[index];
    }

    /**
      * Notification that an entry value has changed after user edit.
      * Implements INodeInfo
      */
    public void actionNodeDataChanged(NodeData data) {
        String dn = getDN();
        LDAPAttribute attr = new LDAPAttribute((String) data.getID(),
                (String) data.getValue());
        LDAPModification modification =
                new LDAPModification(LDAPModification.REPLACE, attr);
        LDAPConnection ldc = getServiceLocator().getConnection();

        if (data.getID().equals("serverHostName")) {
            setName((String) data.getValue());
            _nameNodeData.setValue(data.getValue());
            _nodeDataPanel.setTitle((String) data.getValue());
            if (_viewInstance != null &&
                    _viewInstance instanceof ResourcePage) {
                ResourcePage page = (ResourcePage)_viewInstance;
                if (page.getTreeModel() instanceof ResourceModel) {
                    ((ResourceModel) page.getTreeModel()).
                            fireTreeNodeChanged(this);
                }
            }
        }

        try {
            ldc.modify(dn, modification);
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.NO_SUCH_ATTRIBUTE) {
                try {
                    modification =
                            new LDAPModification(LDAPModification.ADD,
                            attr);
                    ldc.modify(dn, modification);
                } catch (LDAPException ex) {
                    Debug.println(
                            "DomainNode.actionNodeDataChanged() " + ex);
                }
            } else {
                Debug.println("DomainNode.actionNodeDataChanged() " + e);
            }
        }
        isInitialized = false;
    }

    /**
      * Adds change listener
      * allows implenting class to send change notifictions about NodeData
      * Implements INodeInfo
      */
    public void addChangeListener(ChangeListener l) {
        _changeListeners.addElement(l);
    }

    /**
      * Removes change listener
      * Implements INodeInfo
      */
    public void removeChangeListener(ChangeListener l) {
        _changeListeners.removeElement(l);
    }
}
