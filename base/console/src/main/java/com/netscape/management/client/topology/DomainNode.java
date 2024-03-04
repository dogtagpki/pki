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

import java.awt.Component;
import java.text.MessageFormat;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import javax.swing.JCheckBox;
import javax.swing.JPasswordField;
import javax.swing.event.ChangeListener;
import javax.swing.tree.MutableTreeNode;

import com.netscape.management.client.IMenuInfo;
import com.netscape.management.client.IMenuItem;
import com.netscape.management.client.IPage;
import com.netscape.management.client.IResourceObject;
import com.netscape.management.client.ResourceModel;
import com.netscape.management.client.ResourcePage;
import com.netscape.management.client.console.Console;
import com.netscape.management.client.console.ConsoleInfo;
import com.netscape.management.client.console.SplashScreen;
import com.netscape.management.client.util.Debug;
import com.netscape.management.client.util.LDAPUtil;
import com.netscape.management.client.util.RemoteImage;
import com.netscape.management.client.util.ResourceSet;
import com.netscape.management.nmclf.SuiPasswordField;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPModification;
import netscape.ldap.LDAPSearchResults;


/**
 * Tree node of admin group.
 *
 * @author   terencek
 * @version  %I%, %G%
 * @date     9/15/97
 */
public class DomainNode extends ServerLocNode implements IMenuInfo,
INodeInfo {

    private static final String MENU_CONFIGURATION = "CONFIGURATION";

    private static ResourceSet _resource;
    private RemoteImage _icon;
    private ConsoleInfo _consoleInfo;
    private LDAPEntry _infoData;
    private NodeData _nodeData[], _nameNodeData;
    protected NodeDataPanel _nodeDataPanel;
    private Vector _changeListeners = new Vector();

    private String _LDAPHost = null;
    private String _LDAPPort = null;
    private String _subTree = null;
    private String _bindDN = null;
    private String _bindPassword = null;
    private boolean _isSecure = false;

    private IPage _viewInstance;
    private String _dn;

    /**
     * constructor for admin group node.
     *
     * @param sl service locator object
     * @param ldapEntry ldapEntry for the specified node.
     */
    public DomainNode(ServiceLocator sl, LDAPEntry ldapEntry) {
        // set up internal variables
        super(sl);
        _resource = new ResourceSet("com.netscape.management.client.topology.topology");
        _icon = new RemoteImage(_resource.getString("tree", "domainIcon"));

        // NOTE: phlee 02/09/1998
        // The following may be a source for performance problem. However,
        // it is needed in order to retain some unique values for each
        // instance of AdminGroupNode, such as the AdminURL, etc.
        _consoleInfo = (ConsoleInfo) sl.getConsoleInfo().clone();

        _infoData = ldapEntry;
        initialize(_infoData);
    }


    static String i18n(String id) {
        return _resource.getString("DomainNode", id);
    }

    /**
      * load the attribute from the ldapEntry and setup the internal variables
      *
      * @param ldapEntry    ldap entry for the current node.
      */
    private void initialize(LDAPEntry ldapEntry) {
        // BUGBUG: need to get the images
        setIcon(_icon);

        if (ldapEntry == null) {
            Debug.println("ERROR AdminGroupNode.initialize: LDAPEntry is null");
            return;
        }

        setDN(_dn = ldapEntry.getDN());

        String name = null;
        String description = null;
        JCheckBox cbSSL = new JCheckBox();
        SuiPasswordField bindPasswordField = new SuiPasswordField();
        bindPasswordField.setTransparentBorder(true);

        // need to re-read because ldapEntry search was too narrow
        try {
            LDAPAttribute attr;
            LDAPConnection ldc = _consoleInfo.getLDAPConnection();
            LDAPEntry entry = ldc.read(ldapEntry.getDN());
            String locale = LDAPUtil.getLDAPAttributeLocale();
            attr = entry.getAttribute("description", locale);
            description = LDAPUtil.flatting(attr);
            attr = entry.getAttribute("nsAdminDomainName", locale);
            name = LDAPUtil.flatting(attr);
            if (name == null) {
                attr = entry.getAttribute("ou", locale);
                name = LDAPUtil.flatting(attr);
            }
            setName(name);

            String sUG = "cn=UserDirectory, ou=Global Preferences,"+
                    ldapEntry.getDN();
            entry = ldc.read(sUG);

            StringBuffer temp;
            String ldapURL = "";
            attr = entry.getAttribute("nsDirectoryURL");
            if (attr != null) {
                temp = new StringBuffer(LDAPUtil.flatting(attr));

                attr = entry.getAttribute("nsDirectoryFailoverList");
                if ((attr != null) &&
                        ((LDAPUtil.flatting(attr)).equals("") == false))
                    temp.insert(((temp.toString()).lastIndexOf("/")),
                            " " + LDAPUtil.flatting(attr));
                ldapURL = temp.toString();
            }

            if (ldapURL.regionMatches(true, 0, "ldaps",0, 5)) {
                _isSecure = true;
                cbSSL.setSelected(_isSecure);
                _LDAPPort = "636";
            } else
                _LDAPPort = "389";
            int iStart = ldapURL.indexOf("://") + 3;
            int iEnd = ldapURL.indexOf('/',iStart);
            if ((iStart != (-1)) && (iEnd != (-1))) {
                _LDAPHost = ldapURL.substring(iStart, iEnd);
                _subTree = ldapURL.substring(iEnd + 1);
            }
            attr = entry.getAttribute("nsBindDN");
            _bindDN = LDAPUtil.flatting(attr);
            attr = entry.getAttribute("nsBindPassword");
            _bindPassword = LDAPUtil.flatting(attr);
            bindPasswordField.setText(_bindPassword);
        } catch (LDAPException e) {
            System.err.println(e);
        }

        _nodeData = new NodeData[]{
            _nameNodeData = new NodeData("nsAdminDomainName", i18n("nsAdminDomainName"), getName(), true, /*7bit*/false),
            new NodeData("description", i18n("description"), description, true),
            new NodeData("LDAPHost", i18n("LDAPHost"), _LDAPHost, true, true),
            // new NodeData("LDAPPort", i18n("LDAPPort"), _LDAPPort, true),
            new NodeData("SSL", i18n("SSL"), cbSSL, true),
            new NodeData("Subtree", i18n("Subtree"), _subTree, true),
            new NodeData("BindDN", i18n("BindDN"), _bindDN, true),
            new NodeData("BindPassword", i18n("BindPassword"), bindPasswordField, true, true)};
    }

    /**
      * Get a reference to the viewInstance to be used for error message dialog.
      * Also, enable or disable the migration and creation menu items as necessary.
      */
    public void select(IPage viewInstance) {
        _viewInstance = viewInstance;
    }

    /**
      * reload the node information and populate the sub tree with
      * product type node object
      */
    public void reload() {
        super.reload();

        removeAllChildren();

        String _i18nHostsCreatedOutOf =
                Console._resource.getString("splash", "hostsCreatedOutOf");
        String _i18nHostsCreated =
                Console._resource.getString("splash", "hostsCreated");

        long t1, t0 = System.currentTimeMillis();
        int cnt = 0;

        SplashScreen splashScreen = SplashScreen.getInstance();

        removeAllChildren();

        int hostCount = _sl.getHostCount(getDN());
        if (splashScreen != null && hostCount > 0 &&
                System.getProperty("profile") != null) {
            splashScreen.setStatusText( MessageFormat.format(
                    Console._resource.getString("splash", "hostsCount"),
                    new Object[]{ Integer.valueOf(hostCount), getName()}));
        }

        LDAPSearchResults result =
                (LDAPSearchResults) getServiceLocator().getHosts(getDN());
        if (result != null) {
            // load all the hosts object
            long t4, t3 = t0;
            try {
                while (result.hasMoreElements()) {
                    LDAPEntry findEntry = result.next();
                    cnt++;
                    //if (pbar != null) pbar.setValue(cnt);

                    if (cnt >= 20 && cnt % 20 == 0)// update progress every 20 hosts
                    {
                        t4 = System.currentTimeMillis();
                        //Debug.println("ldap Host = " + findEntry.getDN() +"\t" + (t4-t3)/1000. + "sec");
                        t3 = t4;
                        if (splashScreen != null) {
                            if (hostCount > 0) {
                                splashScreen.setStatusText(
                                        MessageFormat.format(
                                        _i18nHostsCreatedOutOf,
                                        new Object[]{ Integer.valueOf(cnt)
                                        , Integer.valueOf(hostCount),
                                        getName()}));

                            } else // do not know what is the total number
                            {
                                splashScreen.setStatusText(
                                        MessageFormat.format(
                                        _i18nHostsCreated,
                                        new Object[]{ Integer.valueOf(cnt)
                                        , getName()}));
                            }
                        }
                    }

                    //HostNode sn = new HostNode( getServiceLocator(), findEntry );
                    LDAPAttribute nameAttr = findEntry.getAttribute("serverhostname");
                    String name = (nameAttr == null) ?
                            _resource.getString("General","noname") :
                            LDAPUtil.flatting(nameAttr);
                    HostNode sn = new HostNode(getServiceLocator(),
                            findEntry.getDN(), name);
                    findEntry = null;


                    if (searchChildByName(sn.getName()) == null) {
                        add(sn);
                    }
                }
            }
            catch (Exception e) {
                // ldap exception
            }
        }

        if (splashScreen != null && cnt > 1) {
            splashScreen.setStatusText(
                    Console._resource.getString("splash", "startingConsole"));
            //splashScreen.setStatusText(
            //    MessageFormat.format(Console._resource.getString("splash", "hostsCreatedDone"),
            //    new Object[] { new Integer(cnt), getName()}));
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
                    Vector vHosts = plugin.getAdditionalChildren(this);
                    if (vHosts != null) {
                        Enumeration eHost = vHosts.elements();
                        while (eHost.hasMoreElements()) {
                            IResourceObject host =
                                    (IResourceObject) eHost.nextElement();
                            if (searchChildByName(host.getName()) == null) {
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
    }


    public String[] getMenuCategoryIDs() {
        return null;
    }


    public IMenuItem[] getMenuItems(String category) {
        return null;
    }

    public void actionMenuSelected(IPage viewInstance, IMenuItem item) {
    }

    /**
      * return the host information panel to the caller
      */
    public Component getCustomPanel() {
        if (_nodeDataPanel == null)
		{
            _nodeDataPanel = new NodeDataPanel(getIcon(), getName(), this);
			_nodeDataPanel.setHelpTopic("admin", "topology-domainnode");
		}
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
      * Number of entries for this node.
      * Implements INodeInfo
      */
    public int getNodeDataCount() {
        return _nodeData.length;
    }


    /**
      * Return node item at specified index.
      * Implements INodeInfo
      */
    public NodeData getNodeData(int index) {
        return _nodeData[index];
    }

    /**
      * Replaces local node data value.  The local node is
      * matched by comparing its name with newData's name.
      */
    public void replaceNodeDataValue(NodeData newData) {
        for (int index = 0; index < _nodeData.length; index++) {
            if (_nodeData[index].getName().equals(newData.getName())) {
                _nodeData[index].setValue(newData.getValue());
                return;
            }
        }
    }

    /**
      * Notification that an entry value has changed after user edit.
      * Implements INodeInfo
      */
    public void actionNodeDataChanged(NodeData data) {
        String dn = _dn;
        boolean fChangeURL = false;

        replaceNodeDataValue(data);

        if ((data.getID().equals("description")) ||
                (data.getID().equals("nsAdminDomainName"))) {
            if (data.getID().equals("nsAdminDomainName")) {
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

            LDAPAttribute attr = new LDAPAttribute(data.getID(),
                    (String) data.getValue());
            LDAPModification modification =
                    new LDAPModification(LDAPModification.REPLACE, attr);
            LDAPConnection ldc = _consoleInfo.getLDAPConnection();
            try {
                ldc.modify(dn, modification);
            } catch (LDAPException e) {
                if (e.getLDAPResultCode() ==
                        LDAPException.NO_SUCH_ATTRIBUTE) {
                    try {
                        modification = new LDAPModification(
                                LDAPModification.ADD, attr);
                        ldc.modify(dn, modification);
                    } catch (LDAPException ex) {
                        Debug.println(
                                "DomainNode.actionNodeDataChanged() " + ex);
                    }
                } else {
                    Debug.println(
                            "DomainNode.actionNodeDataChanged() " + e);
                }
            }
        } else if (data.getID().equals("LDAPHost")) {
            _LDAPHost = (String) data.getValue();
            fChangeURL = true;
        } else if (data.getID().equals("LDAPPort")) {
            _LDAPPort = (String) data.getValue();
            fChangeURL = true;
        } else if (data.getID().equals("SSL")) {
            _isSecure = ((JCheckBox) data.getValue()).isSelected();
            fChangeURL = true;
        } else if (data.getID().equals("Subtree")) {
            _subTree = (String) data.getValue();
            fChangeURL = true;
        } else if (data.getID().equals("BindDN")) {
            _bindDN = (String) data.getValue();
            changeUGAttribute("nsBindDN",_bindDN);
        } else if (data.getID().equals("BindPassword")) {
            _bindPassword = ((JPasswordField) data.getValue()).getText();
            changeUGAttribute("nsBindPassword",_bindPassword);
        }
        if (fChangeURL) {
            String sURL;
            String failoverList;
            int temp;

            if ((temp = _LDAPHost.indexOf(" ")) != -1) {
                // failover list - first host & port is for nsDirectoryURL...
                if (_isSecure)
                    sURL = "ldaps://"+_LDAPHost.substring(0, temp) + "/"+
                            _subTree;
                else
                    sURL = "ldap://"+_LDAPHost.substring(0, temp) + "/"+
                            _subTree;

                // ... and the rest is for nsDirectoryFailoverList
                failoverList = _LDAPHost.substring(temp + 1);
            } else {
                if (_isSecure)
                    sURL = "ldaps://"+_LDAPHost + "/"+_subTree;
                else
                    sURL = "ldap://"+_LDAPHost + "/"+_subTree;

                failoverList = "";
            }

            changeUGAttribute("nsDirectoryURL",sURL);
            changeUGAttribute("nsDirectoryFailoverList",failoverList);
        }
    }

    private void changeUGAttribute(String sAttribute, String sValue) {
        String sEntry = "cn=UserDirectory, ou=Global Preferences,"+_dn;
        LDAPAttribute attr = new LDAPAttribute(sAttribute, sValue);
        LDAPModification modification =
                new LDAPModification(LDAPModification.REPLACE, attr);
        LDAPConnection ldc = _consoleInfo.getLDAPConnection();
        try {
            ldc.modify(sEntry, modification);
        } catch (LDAPException e) {
            if (e.getLDAPResultCode() == LDAPException.NO_SUCH_ATTRIBUTE) {
                try {
                    modification =
                            new LDAPModification(LDAPModification.ADD,
                            attr);
                    ldc.modify(sEntry, modification);
                } catch (LDAPException ex) {
                    Debug.println(
                            "DomainNode.actionNodeDataChanged() " + ex);
                }
            } else {
                Debug.println("DomainNode.actionNodeDataChanged() " + e);
            }
        }
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

    /*
     public int getChildCount()
     {
     	return getServiceLocator().getHostCount(getDN());
     }
     */
}

