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
import java.awt.Cursor;
import java.awt.event.KeyAdapter;
import java.awt.event.MouseAdapter;
import java.text.MessageFormat;
import java.util.Enumeration;
import java.util.Vector;

import javax.swing.JFrame;
import javax.swing.event.ChangeListener;

import com.netscape.management.client.Framework;
import com.netscape.management.client.IMenuInfo;
import com.netscape.management.client.IMenuItem;
import com.netscape.management.client.IPage;
import com.netscape.management.client.IResourceModel;
import com.netscape.management.client.IResourceObject;
import com.netscape.management.client.MenuItemCategory;
import com.netscape.management.client.MenuItemText;
import com.netscape.management.client.ResourceModel;
import com.netscape.management.client.ResourcePage;
import com.netscape.management.client.StatusItemProgress;
import com.netscape.management.client.console.ConsoleInfo;
import com.netscape.management.client.util.ClassLoaderUtil;
import com.netscape.management.client.util.Debug;
import com.netscape.management.client.util.LDAPUtil;
import com.netscape.management.client.util.ModalDialogUtil;
import com.netscape.management.client.util.RemoteImage;
import com.netscape.management.client.util.ResourceSet;
import com.netscape.management.nmclf.SuiOptionPane;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPModification;
import netscape.ldap.LDAPSearchResults;


/**
 * Tree node of admin group.
 *
 * @author   terencek@netscape.com
 * @author   miodrag@netscape.com
 * @author   ahakim@netscape.com
 */
public class AdminGroupNode extends ServerLocNode implements IMenuInfo,
INodeInfo {
    private static final String MENU_OBJECT_CREATE_CATEGORY = "OBJECT_CREATE_CATEGORY";
    private static final String MENU_CONTEXT_CREATE_CATEGORY = "CONTEXT_CREATE_CATEGORY";

    private boolean _enableCreateMenuCategory; // object specific state

    private InstalledProduct[]_installedProducts;

    private static RemoteImage _icon = null;
    private static ProductSelectionDialog _serverSelection = null;
    private static ResourceSet _resource;

    private Vector _changeListeners = new Vector();

    private ConsoleInfo _consoleInfo;
    private String _hostName;
    private String _description;
    private String _groupName;
    private String _installPath;
    private String _adminOS; // Host OS

    protected NodeData _nodeData[], _nameNodeData;
    protected NodeDataPanel _nodeDataPanel;

    protected IPage _viewInstance;


    /**
     * constructor for admin group node.
     *
     * @param sl service locator object
     * @param ldapEntry ldapEntry for the specified node.
     */
    public AdminGroupNode(ServiceLocator sl, LDAPEntry ldapEntry) {
        // set up internal variables
        super(sl);
        _resource = new ResourceSet("com.netscape.management.client.topology.topology");
        _icon = new RemoteImage(_resource.getString("tree", "folderIcon"));

        // NOTE: phlee 02/09/1998
        // The following may be a source for performance problem. However,
        // it is needed in order to retain some unique values for each
        // instance of AdminGroupNode, such as the AdminURL, etc.
        _consoleInfo = (ConsoleInfo) sl.getConsoleInfo().clone();

        initialize(ldapEntry);

        // Initialized at first migration/creation.
        _installedProducts = null;

        initializeMenuItems();
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

        LDAPAttributeSet findAttrs = ldapEntry.getAttributeSet();
        Enumeration enumAttrs = findAttrs.getAttributes();

        setDN(ldapEntry.getDN());
        setName( LDAPUtil.flatting( ldapEntry.getAttribute("cn",
                LDAPUtil.getLDAPAttributeLocale())));

        // get the important attributes from the server entry
        while (enumAttrs.hasMoreElements()) {
            LDAPAttribute anAttr = (LDAPAttribute) enumAttrs.nextElement();
            String attrName = anAttr.getName();

            if (attrName.equalsIgnoreCase("nsAdminGroupName")) {
                _groupName = LDAPUtil.flatting(anAttr.getStringValues());
                setName(LDAPUtil.flatting(anAttr.getStringValues()));
            } else if (attrName.equalsIgnoreCase("description")) {
                _description = LDAPUtil.flatting(anAttr.getStringValues());
            } else if (attrName.equalsIgnoreCase("nsConfigRoot")) {
                _installPath = LDAPUtil.flatting(anAttr.getStringValues());
            }
        }

        // set the admin url.
        String ldapAdminServer =
                getServiceLocator().getAdminServer(getDN());
        if (ldapAdminServer != null) {
            try {
                String adminURL = findAdminURL(_consoleInfo, ldapAdminServer);
                _consoleInfo.setAdminURL(adminURL);
            }
            catch (Exception e) {
                _consoleInfo.setAdminURL("");
                Debug.println(0, "ERROR AdminGroupNode.initialize: can not determine adminURL, possibly corrupted DS config data");
            }
        }

        _nodeData = new NodeData[]{ _nameNodeData =
                new NodeData("nsAdminGroupName",
                _resource.getString("ServerObject",
                "nsAdminGroupName"), getName(), true, true),
        new NodeData("description",
                _resource.getString("ServerObject","description"),
                _description, true), };
    }

    /**
      * initialize menu items
      */
    private void initializeMenuItems() {
        // Remember the state determined in getInstalledProducts() method.
        _enableCreateMenuCategory = false;
    }

    /**
      * Get all installed products.
      */
    private void getInstalledProducts() {
        LDAPSearchResults apps = getApplications();
        if (apps == null) {
            return;
        }

        LDAPEntry entry;

        String name; // Required
        String nickname; // Required
        String creationClassName; // Optional
        String description; // Optional
        Vector products = new Vector();
        try {
            while (apps.hasMoreElements()) {
                entry = apps.next();

                name = LDAPUtil.flatting(
                        entry.getAttribute("nsproductname",
                        LDAPUtil.getLDAPAttributeLocale()));
                if (name == null || name.equals("")) {
                    Debug.println("TRACE AdminGroupNode.getInstalledProducts: no value for nsproductname attribute.");
                    continue;
                }

                nickname = LDAPUtil.flatting(
                        entry.getAttribute("nsnickname",
                        LDAPUtil.getLDAPAttributeLocale()));
                if (nickname == null || nickname.equals("")) {
                    Debug.println("TRACE AdminGroupNode.getInstalledProducts: no value for nsnickname attribute.");
                    continue;
                }

                creationClassName = LDAPUtil.flatting(
                        entry.getAttribute("nsservercreationclassname",
                        LDAPUtil.getLDAPAttributeLocale()));
                if (creationClassName != null &&
                        creationClassName.equals("") != true) {
                    _enableCreateMenuCategory = true; // object specific state
                }
                description = LDAPUtil.flatting(
                        entry.getAttribute("description",
                        LDAPUtil.getLDAPAttributeLocale()));

                products.addElement( new InstalledProduct(name, nickname,
                        creationClassName, description));
            }
        } catch (Exception e) {
            // ldap exception
        }

        if (products.size() == 0) {
            Debug.println(
                    "TRACE AdminGroupNode.getInstalledProducts: this admin group contains no products: " +
                    getDN());
            return;
        }

        _installedProducts = new InstalledProduct[products.size()];
        products.copyInto(_installedProducts);
    }


    /**
      * Get all the server ID's under the Admin Group Node.
      */
    public Vector getServerIDs() {
        String id;
        Vector serverIDs = new Vector();
        ServiceLocator sl = getServiceLocator();

        LDAPSearchResults result =
                (LDAPSearchResults) sl.getProductType(getDN());
        try {
            while (result.hasMoreElements()) {
                LDAPEntry ldapEntry = result.next();
                LDAPSearchResults eResult = sl.getSIE(ldapEntry.getDN());
                while (eResult.hasMoreElements()) {
                    LDAPEntry serverInstanceEntry =
                            eResult.next();
                    id = LDAPUtil.flatting(
                            serverInstanceEntry.getAttribute("nsserverid",
                            LDAPUtil.getLDAPAttributeLocale()));
                    if (id != null && id.equals("") == false)
                        serverIDs.addElement(id);
                }
            }
        } catch (Exception e) {
            // ldap exception
        }
        return serverIDs;
    }


    /**
      * Get a reference to the viewInstance to be used for error message dialog.
      * Also, enable or disable the migration and creation menu items as necessary.
      */
    public void select(IPage viewInstance) {
        _viewInstance = viewInstance;
        if ((viewInstance instanceof ResourcePage) == false) {
            return;
        }
        ResourcePage rp = (ResourcePage) viewInstance;
        IResourceObject[] selection = rp.getSelection();
        ResourceModel rpm = (ResourceModel) rp.getModel();

        // Enable or disable based on selection count
        if (selection != null && selection.length == 1) {
            if (_enableCreateMenuCategory) {
                rpm.fireEnableMenuItem(viewInstance,
                        MENU_OBJECT_CREATE_CATEGORY);
                rpm.fireEnableMenuItem(viewInstance,
                        MENU_CONTEXT_CREATE_CATEGORY);
            } else {
                rpm.fireDisableMenuItem(viewInstance,
                        MENU_OBJECT_CREATE_CATEGORY);
                rpm.fireDisableMenuItem(viewInstance,
                        MENU_CONTEXT_CREATE_CATEGORY);
            }
        } else {
            rpm.fireDisableMenuItem(viewInstance,
                    MENU_OBJECT_CREATE_CATEGORY);
            rpm.fireDisableMenuItem(viewInstance,
                    MENU_CONTEXT_CREATE_CATEGORY);
        }
    }


    /**
      * set the admin server os type
      *
      * @param os OS description string
      */
    public void setAdminOS(String os) {
        _adminOS = os;
    }


    /**
      * reload the node information and populate the sub tree with
      * product type node object
      */
    public void reload() {
        Debug.println(Debug.TYPE_RSPTIME, "Reload Admin Group node ...");
        Vector productTypeList = new Vector();

        removeAllChildren();
        super.reload();

        ServiceLocator sl = getServiceLocator();

        if (_adminOS != null)
            _consoleInfo.setAdminOS(_adminOS);

        LDAPSearchResults result =
                (LDAPSearchResults) sl.getProductType(getDN());
        try {
            while (result.hasMoreElements()) {
                LDAPEntry ldapEntry = result.next();

                LDAPSearchResults eResult = sl.getSIE(ldapEntry.getDN());
                while (eResult.hasMoreElements()) {
                    LDAPEntry serverInstanceEntry =
                            eResult.next();
                    ServerNode sn = new ServerNode(_consoleInfo, sl,
                            serverInstanceEntry);

                    if (searchChildByName(sn.getName()) == null) {
                        add(sn);
                    }
                }
            }
            _fLoaded = true;
        } catch (Exception e) {
            // ldap exception
        }
        Debug.println(Debug.TYPE_RSPTIME, "Admin Group node reloaded");
    }

    /**
      * test whether the given SIE is admin server or not
      *
      * @param ldapEntry LDAP entry for the SIE
      * @return true if the given entry is an admin server. false otherwise
      */
    private boolean isAdminServer(LDAPEntry ldapEntry) {
        LDAPAttributeSet findAttrs = ldapEntry.getAttributeSet();
        Enumeration enumAttrs = findAttrs.getAttributes();
        while (enumAttrs.hasMoreElements()) {
            LDAPAttribute attribute =
                    (LDAPAttribute) enumAttrs.nextElement();
            String name = attribute.getName();
            if (name.equalsIgnoreCase("cn")) {
                String value =
                        LDAPUtil.flatting(attribute.getStringValues());
                if (value.indexOf("admin") != -1)
                    return true;
            }
        }
        return false;
    }

    /**
      * given an ldap entry and try to find the admin URL for that ldap entry
      *
      * @param consoleInfo global information
      * @param ldapEntry SIE trny
      * @return admin server URL string
      */
    public static String findAdminURL(ConsoleInfo consoleInfo,
            String ldapDN) {
        String host = null;
        boolean security = false;
        String port = null;
        String dn = null;
        try {
            LDAPConnection ldc = consoleInfo.getLDAPConnection();
            if (ldc != null) {
                LDAPEntry configLdapEntry =
                        ldc.read(dn = "cn=configuration,"+ldapDN);
                if (configLdapEntry != null) {
                    LDAPAttributeSet attributeSet =
                            configLdapEntry.getAttributeSet();
                    Enumeration attributes = attributeSet.getAttributes();

                    while (attributes.hasMoreElements()) {
                        LDAPAttribute attribute =
                                (LDAPAttribute) attributes.nextElement();
                        String name = attribute.getName();
                        if (name.equalsIgnoreCase("nsServerPort")) {
                            port = LDAPUtil.flatting(
                                    attribute.getStringValues());
                        } else if (name.equalsIgnoreCase("nsServerAddress")) {
                            host = LDAPUtil.flatting(
                                    attribute.getStringValues());
                        } else if (name.equalsIgnoreCase("nsServerSecurity")) {
                            String value = LDAPUtil.flatting(
                                    attribute.getStringValues());
                            if (value.equalsIgnoreCase("on"))
                                security = true;
                        }
                    }
                }

                /*
                 * nsserveraddress might not be defined, which means that the
                 * admin server should listen on all interfaces rather than on
                 * a specific one. Read serverhostname from the SIE entry.
                 * admin server uses 0.0.0.0 to mean listen on all interfaces
                 */
                if ((host == null) || (host.trim().length() == 0) || host.equals("0.0.0.0")) {
                    LDAPEntry sieEntry = ldc.read(dn=ldapDN, new String[] {"serverhostname"});
                    if (sieEntry == null) {
                        Debug.println(0, "AdminGroupNode.findAdminURL: " +
                         "could not get serverhostname from " + ldapDN);
                        return null;

                     }
                     host = LDAPUtil.flatting(sieEntry.getAttribute("serverhostname"));
                }
            }
        } catch (LDAPException e) {
            Debug.println("AdminGroupNode.findAdminURL: LDAP Error: "+
                    e + " try to open:"+dn);
            return null;
        }
        String url = "http";
        if (security)
            url = url + "s";
        url = url + "://" + host + ":" + port + "/";
        return url;
    }

    /**
      * return the menu category
      *
      * @return list of affect menu categories
      */
    public String[] getMenuCategoryIDs() {
        if (_installedProducts == null) {
            getInstalledProducts();
        }

        if (_enableCreateMenuCategory) {
            return new String[]{ ResourcePage.MENU_OBJECT,
            ResourcePage.MENU_CONTEXT,
            AdminGroupNode.MENU_OBJECT_CREATE_CATEGORY,
            AdminGroupNode.MENU_CONTEXT_CREATE_CATEGORY };
        } else {
            return new String[]{ ResourcePage.MENU_OBJECT,
            ResourcePage.MENU_CONTEXT };
        }
    }


    /**
      * return a list of menu item for the given category
      *
      * @param category menu category
      * @return the menu item for the given category
      */
    public IMenuItem[] getMenuItems(String category) {
        if (category.equals(ResourcePage.MENU_OBJECT)) {
            return new IMenuItem[]{ new MenuItemCategory(
                    MENU_OBJECT_CREATE_CATEGORY,
                    _resource.getString("menu", "CreateServer"),
                    _enableCreateMenuCategory)};
        } else if (category.equals(ResourcePage.MENU_CONTEXT)) {
            return new IMenuItem[]{ new MenuItemCategory(
                    MENU_CONTEXT_CREATE_CATEGORY,
                    _resource.getString("menu", "CreateServer"),
                    _enableCreateMenuCategory)};
        } else if (category.equals(MENU_OBJECT_CREATE_CATEGORY) ||
                category.equals(MENU_CONTEXT_CREATE_CATEGORY)) {
            if (_installedProducts == null) {
                getInstalledProducts();
            }
            if (_installedProducts != null) {
                // Create a menu item for each installed product which has a creation class name,
                Vector v = new Vector();
                String classname;
                for (int i = 0; i < _installedProducts.length; i++) {
                    classname =
                            _installedProducts[i].getCreationClassName();
                    if (classname != null && classname.equals("") != true) {
                        v.addElement( new MenuItemText(
                                _installedProducts[i].getNickname(),
                                _installedProducts[i].getName(),
                                _installedProducts[i].getDescription()));
                    }
                }
                if (v.size() != 0) {
                    IMenuItem[] menuItems = new IMenuItem[v.size()];
                    v.copyInto(menuItems);
                    return menuItems;
                }
            }
        }

        return null;
    }

    /**
      * perform action for the menu item
      *
      * @param viewInstance view instance of the console
      * @param item menu item which is selected
      */
    public void actionMenuSelected(IPage viewInstance, IMenuItem item) {
        // Check if create a new server instance was selected.
        if (_installedProducts != null) {
            for (int i = 0; i < _installedProducts.length; i++) {
                if (item.getID().equals(
                        _installedProducts[i].getNickname())) {
                    Class c = ClassLoaderUtil.getClass(_consoleInfo,
                            _installedProducts[i]
                            .getCreationClassName());
                    if (c != null) {
                        try {
                            IProductObject productHandle =
                                    (IProductObject) c.newInstance();
                            productHandle.initialize(
                                    (ConsoleInfo)_consoleInfo.clone());
                            CreateThread thread =
                                    new CreateThread(_consoleInfo,
                                    viewInstance, getDN(),
                                    productHandle, _resource);
                            thread.start();
                        } catch (Exception e) {
                            SuiOptionPane.showMessageDialog(
                                    _consoleInfo.getFrame(),
                                    MessageFormat.format(
                                    _resource.getString("ServerPromptDialog",
                                    "couldNotInstantiate"),
                                    new Object[]{c.getName(), e}),
                                    _resource.getString("ServerPromptDialog",
                                    "CreateTitle"),
                                    SuiOptionPane.ERROR_MESSAGE);
                            ModalDialogUtil.sleep();
                            ModalDialogUtil.raise(
                                    viewInstance.getFramework().
                                    getJFrame());
                            return;
                        }
                    }
                    break; // Only one instance can be created at a time...
                }
            }
        }
    }


    /**
      * Inform the model that the structure has changed.
      */
    private synchronized void reloadModel(IPage viewInstance) {
        if (viewInstance instanceof ResourcePage) {
            IResourceModel im = ((ResourcePage) viewInstance).getModel();
            if (im instanceof TopologyModel) {
                TopologyModel tm = (TopologyModel) im;
                try {
                    Thread.sleep(500); // Fixes timing problem associated with refreshing the tree
                    tm.refreshTree(viewInstance);
                } catch (Exception e) {
                }
            }
        }
    }

    /**
      * return the configuration panel
      *
      * @return configuration panel
      */
    public Component getCustomPanel() {
        _nodeDataPanel = new NodeDataPanel(getIcon(), getName(), this);
		_nodeDataPanel.setHelpTopic("admin", "topology-groupnode");
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
      * Number of entries for this node.
      * Implements INodeInfo
      */
    public int getNodeDataCount() {
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
        replaceNodeDataValue(data);

        String dn = getDN();
        LDAPAttribute attr = new LDAPAttribute(data.getID(),
                (String) data.getValue());
        LDAPModification modification =
                new LDAPModification(LDAPModification.REPLACE, attr);
        LDAPConnection ldc = getServiceLocator().getConnection();

        if (data.getID().equals("nsAdminGroupName")) {
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

    /**
      * Return a list of applications installed in this admin group.
      */
    public LDAPSearchResults getApplications() {
        LDAPSearchResults result = null;
        String filter = "(ObjectClass=nsApplication)";

        try {
            LDAPConnection ldc = _consoleInfo.getLDAPConnection();
            if (ldc != null) {
                result = ldc.search(getDN(), LDAPConnection.SCOPE_ONE,
                        filter, null, false);
            }

        } catch (LDAPException e) {
            Debug.println(
                    "ERROR AdminGroupNode.getApplications: LDAP search failed: " +
                    filter);
            return null;
        }

        return result;
    }

    // Used to temporarily grab input for JFrame glass pane, which disables
    // user input while a task thread is being run.
    private static KeyAdapter _tmpGrabKey = new KeyAdapter() {};
    private static MouseAdapter _tmpGrabMouse = new MouseAdapter() {};

    /**
     * Grab or release user input.
     *
     * @param viewInstance  console view
     * @param value         grab user input if true, release if false
     */
    private synchronized void setGrabAllInput(IPage viewInstance,
            boolean value) {
        JFrame frame = viewInstance.getFramework().getJFrame();
        Component glassPane = frame.getGlassPane();
        if (value) {
            glassPane.addKeyListener(_tmpGrabKey);
            glassPane.addMouseListener(_tmpGrabMouse);
            glassPane.setVisible(true);
        } else {
            glassPane.removeKeyListener(_tmpGrabKey);
            glassPane.removeMouseListener(_tmpGrabMouse);
            glassPane.setVisible(false);
        }
    }


    /**
      * display the busy signal
      *
      * @param viewInstance console view
      * @param isBusy boolean flag to indicate busy
      * @param status status text to be displayed
      */
    private synchronized void setBusyIndicator(IPage viewInstance,
            boolean isBusy, String status) {
        setGrabAllInput(viewInstance, isBusy);

        if ((viewInstance instanceof ResourcePage) == false) {
            return;
        }
        ResourcePage rp = (ResourcePage) viewInstance;
        IResourceObject[] selection = rp.getSelection();
        ResourceModel rpm = (ResourceModel) rp.getModel();

        if (isBusy == true) {
            viewInstance.getFramework().setCursor(
                    Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
            rpm.fireChangeStatusItemState(null, Framework.STATUS_TEXT,
                    status);
            rpm.fireChangeStatusItemState(null,
                    ResourcePage.STATUS_PROGRESS,
                    StatusItemProgress.STATE_BUSY);
        } else {
            viewInstance.getFramework().setCursor(
                    Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
            rpm.fireChangeStatusItemState(null, Framework.STATUS_TEXT,
                    status);
            rpm.fireChangeStatusItemState(null,
                    ResourcePage.STATUS_PROGRESS, Integer.valueOf(0));
        }
    }

    /**
      * inner class to handle server creation
      */
    class CreateThread extends Thread {
        ConsoleInfo _consoleInfo;
        IPage _viewInstance;
        String _currentDN;
        IProductObject _productHandle;
        ResourceSet _resource;

        public CreateThread(ConsoleInfo consoleInfo,
                IPage viewInstance, String currentDN,
                IProductObject productHandle, ResourceSet resource) {
            _consoleInfo = consoleInfo;
            _viewInstance = viewInstance;
            _currentDN = currentDN;
            _productHandle = productHandle;
            _resource = resource;
        }

        public void run() {
            // Catch exception as a defensive measure to prevent the
            // run method from exiting without unsetting the busy
            // indicator which effectively hangs the console.
            try {
                AdminGroupNode.this.setBusyIndicator(_viewInstance,
                        true, _resource.getString("status", "creatingServer"));
                if (_productHandle.createNewInstance(_currentDN) == true) {
                    AdminGroupNode.this.setBusyIndicator(_viewInstance,
                            false, "");
                    AdminGroupNode.this.setBusyIndicator(_viewInstance,
                            true, _resource.getString("status", "refreshingTopology"));
                    AdminGroupNode.this.reloadModel(_viewInstance); // Inform the model that the structure has changed.
                    AdminGroupNode.this.syncTaskSIEData(_consoleInfo);
                }
            } catch (Exception e) {
            }
            finally { AdminGroupNode.this.setBusyIndicator(
                    _viewInstance, false, "");
            } }
    }
}


/**
  * Class used to store the necessary information about the products
  * installed in the current administration group.
  */
class InstalledProduct {
    private String _name;
    private String _nickname;
    private String _creationClassName;
    private String _description;

    public InstalledProduct(String name, String nickname,
            String creationClassName, String description) {
        _name = name;
        _nickname = nickname;
        _creationClassName = creationClassName;
        _description = description;
    }

    public String getName() {
        return _name;
    }

    public String getNickname() {
        return _nickname;
    }

    public String getCreationClassName() {
        return _creationClassName;
    }

    public String getDescription() {
        return _description;
    }
}


