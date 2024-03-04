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

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyAdapter;
import java.awt.event.MouseAdapter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Locale;
import java.util.StringTokenizer;
import java.util.Vector;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JSeparator;
import javax.swing.JTextArea;
import javax.swing.UIManager;
import javax.swing.border.Border;

import com.netscape.management.client.Framework;
import com.netscape.management.client.IMenuInfo;
import com.netscape.management.client.IMenuItem;
import com.netscape.management.client.IPage;
import com.netscape.management.client.IResourceModel;
import com.netscape.management.client.IResourceObject;
import com.netscape.management.client.MenuItemSeparator;
import com.netscape.management.client.MenuItemText;
import com.netscape.management.client.ResourceModel;
import com.netscape.management.client.ResourceModelEvent;
import com.netscape.management.client.ResourceObject;
import com.netscape.management.client.ResourcePage;
import com.netscape.management.client.StatusItemProgress;
import com.netscape.management.client.components.StatusDialog;
import com.netscape.management.client.components.UIConstants;
import com.netscape.management.client.console.ConsoleInfo;
import com.netscape.management.client.ug.ResourceEditor;
import com.netscape.management.client.util.ClassLoaderUtil;
import com.netscape.management.client.util.Debug;
import com.netscape.management.client.util.IProgressListener;
import com.netscape.management.client.util.JButtonFactory;
import com.netscape.management.client.util.LDAPUtil;
import com.netscape.management.client.util.LocalJarClassLoader;
import com.netscape.management.client.util.ModalDialogUtil;
import com.netscape.management.client.util.RemoteImage;
import com.netscape.management.client.util.ResourceSet;
import com.netscape.management.client.util.UtilConsoleGlobals;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPSearchConstraints;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.LDAPSortKey;
import netscape.ldap.controls.LDAPSortControl;


/**
  * Server node object in the topology view.
  *
  * @author Andy Hakim
  * @author Miodrag Keckic
  * @author Terence Kwan
  */
public class ServerNode extends ServerLocNode implements IMenuInfo
{
    private static final String ERROR_PREFIX = "error"; // prefix used for retrieving values in ResourceSet

    // MENU_ are public to allow server objects to enable/disable menus, a terrible hack
    public static final String MENU_SET_ACL = "setAcl";
    public static final String MENU_OPEN_SERVER = "open";
    public static final String MENU_CLONE_SERVER = "clone";
    public static final String MENU_REMOVE_SERVER = "remove";

    private boolean enableSetACLMenuItem = false;
    private boolean enableOpenMenuItem = true; // This option is always enabled
    private boolean enableCloneMenuItem = false;
    private boolean enableRemoveMenuItem = false;

    // UI related
    private static ResourceSet resource = new ResourceSet("com.netscape.management.client.topology.topology");
    private IPage viewInstance = null;
    private JFrame parentFrame = null;
    private StatusDialog statusDialog = null;

    // Session related
    private ConsoleInfo consoleInfo;
    private LDAPConnection ldc;
    private LDAPEntry ldapEntry;
    private String topologyDN;

    // Server related
    private IServerObject serverObject;
    private static Hashtable serverObjectsCache = new Hashtable(); // used to cache IServerObject for cloning
    private boolean isSelectPending = false;                // true if select() called when jar not loaded
    private Component customPanel = null;

    private String cacheIconPath;
    // An icon that denotes that server jar is not available on the local disk
    private static RemoteImage noJarIcon = new RemoteImage(resource.getString("tree", "noJarIcon"));
    // An icon that denotes that server jar download failed, or the instance could not be created
    private static RemoteImage failedLoadIcon = new RemoteImage(resource.getString("tree", "failedLoadIcon"));

    // Server Cloning
    private static ProductSelectionDialog cloneSelection = null;
    private static String[]nicknameList = null; // used to cache nicknames used to filter IServerObjects for cloning

    //private boolean testJarLoadFailure = true;

    /**
     * constructor
     *
     * @param sl service locator object which use to find other servers
     * @param ldapEntry LDAP Entry for the server
     */
    public ServerNode(ServiceLocator sl, LDAPEntry ldapEntry)
    {
        this(sl.getConsoleInfo(), sl, ldapEntry);
    }


    /**
     * constructor with given console info object
     *
     * @param ci global information
     * @param sl service locator object which use to find other servers
     * @param ldapEntry LDAP Entry for the server
     */
    public ServerNode(ConsoleInfo ci, ServiceLocator sl, LDAPEntry ldapEntry)
    {
        super(sl);
        this.ldapEntry = ldapEntry;
        this.consoleInfo = ci; // Use the Admin Group that this belongs to.
        this.ldc = ci.getLDAPConnection();
        setDN(ldapEntry.getDN());
        initialize(ldapEntry);
    }

    /**
     * initialize routine
     *
     * @param ldapEntry the server's ldap entry
     */
    public void initialize(LDAPEntry ldapEntry)
    {
        String serverName = LDAPUtil.flatting(ldapEntry.getAttribute("serverProductName", LDAPUtil.getLDAPAttributeLocale()));
        if (serverName == null)
            serverName = LDAPUtil.flatting( ldapEntry.getAttribute("cn", LDAPUtil.getLDAPAttributeLocale()));

        String serverDN = ldapEntry.getDN();
        topologyDN = serverDN;

        // Set default name and icon
        setName(serverName);
        setIcon(noJarIcon);

        // Lookup the server object in the cache.
        Object obj = serverObjectsCache.get(serverDN);

        if (obj != null)
            {
                _fLoaded = true;
                serverObject = (IServerObject) obj;
                if (((ResourceObject)serverObject).getName() != null)
                    setName(((ResourceObject)serverObject).getName());

                if (serverObject instanceof AbstractServerObject) {
                    ((AbstractServerObject)serverObject).setNodeObject(this);
                }

                setIcon(serverObject.getIcon());
            }
        else
            {
                // Try to present server object in the topology without creating the
                // object instance. Look for the cached server icon in <jarName>.icon file.
                String jarName = getJARClassName(ldc, serverDN);
                /* Serializing the icon to cache it no longer seems to be
                 * working correctly.  We will instantiate the server now
                 * instead.
                 *
                String jarBaseName  = jarName; // jar name without extension
                if (jarName.indexOf('.') > 0)
                    {
                        jarBaseName = jarName.substring(0, jarName.indexOf('.'));
                    }
                cacheIconPath = LocalJarClassLoader.jarsDir + jarBaseName + ".icon";
                ImageIcon icon = (ImageIcon)getIconFromCache(cacheIconPath);
                if (icon != null)
                    {
                        setIcon(icon);
                    }
                else
                    { */
                        // Instantiate the server object if it's jar is available
                        if (ClassLoaderUtil.isAlreadyDownload(jarName))
                            {
                                reload();
                            }
                        else
                            {
                                String compatibleJar = LocalJarClassLoader.checkForNewerVersion(jarName);
                                if (compatibleJar != null && ClassLoaderUtil.isAlreadyDownload(compatibleJar))
                                    {
                                        reload();
                                    }
                            }
                    /* } */
            }
    }

    /**
     * Creates instance of a server object. If the real instance can not be created,
     * due to a jar download failure or some other reason, a dummy instance is created
     * in order to provide default server info in the RHP. Otherwise, RHP would
     * be empty.
     */
    public void reload()
    {
        if (!_fLoaded && serverObject == null)
            {
            _fLoaded  = true;
            serverObject = createServerInstance(topologyDN, getName(), true);
            if (serverObject != null)
                {
                    if (((ResourceObject)serverObject).getName() != null)
                        ServerNode.this.setName(((ResourceObject)serverObject).getName());

                    if (serverObject instanceof AbstractServerObject)
                        {
                            ((AbstractServerObject)serverObject).setNodeObject(ServerNode.this);
                        }

                    setIcon(serverObject.getIcon());
            /*        if (cacheIconPath != null)
                        {
                            ImageIcon icon =(ImageIcon)serverObject.getIcon();

                            // Craete a new Icon object. Circumvent RemoteImage as
                            // it might have different version from one jar to another
                            cacheIcon(cacheIconPath, new ImageIcon(icon.getImage()));
                        }
            */

                    customPanel = serverObject.getCustomPanel();
                }
            else // failed
                {
                    setIcon(failedLoadIcon);
                    customPanel = new ServerLoadFailedPanel(getName());
                }

            if(viewInstance != null)
                {
                    ResourcePage page = (ResourcePage) viewInstance;
                    ResourceModel model = (ResourceModel) page.getModel();
                    page.changeCustomPanel(new ResourceModelEvent(model, page, customPanel));
                }

            if(isSelectPending && viewInstance != null)
                {
                    isSelectPending = false;
                    select(viewInstance);
                }
            }
    }

    /**
     * Serialize icon and store in cache
     */
    private static void cacheIcon(String file, Object obj)
    {
        FileOutputStream fos = null;
        ObjectOutputStream  objos = null;

        try
            {
                fos = new FileOutputStream(new File(file));
                objos = new ObjectOutputStream(fos);
                objos.writeObject(obj);
                objos.flush();
            }
        catch(Exception ex)
            {
                Debug.println(0, "Failed to serialize " + file + " "  + ex);
            }
        finally
            {
                try
                    {
                        if (objos != null)
                            {
                                objos.close();
                            }
                        if (fos != null)
                            {
                                fos.close();
                            }
                    }
                catch (Exception ex) {}
            }
    }

    /**
     * Get Icon from cache
     */
    private static Object getIconFromCache(String file)
    {
        FileInputStream fis = null;
        ObjectInputStream  objis = null;

        try
            {
                fis = new FileInputStream(new File(file));
                objis = new ObjectInputStream(fis);
                return objis.readObject();
            }
        catch(java.io.FileNotFoundException ex)
            {
                ; // Ignore
            }
        catch(Exception ex)
            {
                Debug.println(0, "Failed to deserialize " + file + " "  + ex);
            }
        finally
            {
                try
                    {
                        if (objis != null)
                            {
                                objis.close();
                            }
                        if (fis != null)
                            {
                                fis.close();
                            }
                    }
                catch (Exception ex) {}
            }
        return null;
    }

    /**
     * returns true if server node corresponds to MCC Registry DS instance
     */
    private boolean isMCCRegistryServer()
    {
        String hostname = LDAPUtil.flatting(ldapEntry.getAttribute("serverhostname", LDAPUtil.getLDAPAttributeLocale()));
        String port = LDAPUtil.flatting(ldapEntry.getAttribute("nsserverport", LDAPUtil.getLDAPAttributeLocale()));

        if ((consoleInfo.getHost().equals(hostname)) &&
            (String.valueOf(consoleInfo.getPort()).equals(port))) {
            return true;
        }
        else
            {
                return false;
            }
    }

    /**
     * call whether the node is unselected.
     *
     * @param viewInstance console's instance
     */
    public void unselect(IPage viewInstance)
    {
        if (serverObject != null)
            {
                serverObject.unselect(viewInstance);
            }
    }

    /**
     * call whether the node is selected.
     *
     * @param viewInstance console's instance
     */
    public void select(IPage viewInstance)
    {
        this.viewInstance = viewInstance;
        this.parentFrame = viewInstance.getFramework().getJFrame();

        if (serverObject == null)
            {
                reload();
            }

        if (serverObject != null)
            {
                if ((viewInstance instanceof ResourcePage) == false)
                    {
                        return;
                    }

                // Setting this here allows this to be accessed from
                // the actionMenuSelected() method.
                ResourcePage rp = (ResourcePage) viewInstance;
                IResourceObject[] selection = rp.getSelection();
                ResourceModel rpm = (ResourceModel) rp.getModel();

                if (selection != null && selection.length == 1)
                    {
                        enableSetACLMenuItem = true;
                        enableCloneMenuItem = false;
                        if (serverObject instanceof AbstractServerObject)
                            {
                                AbstractServerObject aso = (AbstractServerObject)serverObject;
                                enableSetACLMenuItem = aso.isACLEnabled();
                                enableCloneMenuItem = aso.isCloningEnabled();
                            }
                        // Enable or disable based on instance kind. Need to determine based on selection
                        // count since we don't want the state of the remove menu item to be solely
                        // determined by the last selected ServerNode.
                        if ((serverObject instanceof IRemovableServerObject) && (isMCCRegistryServer() == false))
                            enableRemoveMenuItem = true;
                        else
                            enableRemoveMenuItem = false;
                    }
                else
                    {
                        enableSetACLMenuItem = false;
                        enableCloneMenuItem = false;

                        // Enable or disable based on instance kind. Need to determine based on selection
                        // count since we don't want the state of the remove menu item to be solely
                        // determined by the last selected ServerNode.
                        enableRemoveMenuItem = isRemovable(selection);
                    }

                if (enableSetACLMenuItem)
                    rpm.fireEnableMenuItem(viewInstance, MENU_SET_ACL);
                else
                    rpm.fireDisableMenuItem(viewInstance, MENU_SET_ACL);
                if (enableCloneMenuItem)
                    rpm.fireEnableMenuItem(viewInstance, MENU_CLONE_SERVER);
                else
                    rpm.fireDisableMenuItem(viewInstance, MENU_CLONE_SERVER);
                if (enableRemoveMenuItem)
                    rpm.fireEnableMenuItem(viewInstance, MENU_REMOVE_SERVER);
                else
                    rpm.fireDisableMenuItem(viewInstance, MENU_REMOVE_SERVER);

                serverObject.select(viewInstance);
            }
        else
            isSelectPending = true;
    }

    /**
     * check whether the node is removable or not
     *
     * @param selection list of currently selected object
     * @return true if they are removeable. false otherwise
     */
    private boolean isRemovable(IResourceObject[] selection)
    {
        ServerNode snode = null;
        IServerObject snodeObject = null;
        for (int i = 0; i < selection.length; i++)
            {
                // If every selected object is not a ServerNode, then we don't really
                // need to check this since the remove menu item won't even appear.
                // However, keep the check for completeness.
                if (selection[i] instanceof ServerNode)
                    {
                        snode = (ServerNode)(selection[i]);
                        snodeObject = snode.getServerObject();
                        if ((snodeObject == null) || ((snodeObject instanceof IRemovableServerObject) == false) || snode.isMCCRegistryServer())
                            {
                                return false;
                            }
                    }
                else
                    {
                        return false;
                    }
            }
        return true;
    }


    /**
     * Overloads ResourceObject.getClassName because we want to compare this object's
     * IServerObject classname, not this ServerNode classname!
     */
    public String getClassName()
    {
        if (serverObject != null)
            {
                return serverObject.getClass().getName();
            }
        return super.getClassName();
    }

    /**
     * user double click on the objects. We do something about it. We will
     * start a thread and run the server configuration framework.
     *
     * @param viewInstance console instance
     * @param selection array of current selection
     */
    public boolean run(IPage viewInstance, IResourceObject[] selection)
    {
        if (serverObject != null)
            {
                if (Debug.timeTraceEnabled())
                    {
                        Debug.println(Debug.TYPE_RSPTIME, "Open " + getName() + " ...");
                    }
                ServerRunThread thread = new ServerRunThread(serverObject, viewInstance, selection);
                thread.start();
                return true;
            }
        else
            {
                reload();
            }

        return false;
    }

    /**
     * get the right hand panel of the node
     *
     * @return right hand panel
     */
    public Component getCustomPanel()
    {
        if (serverObject == null)
            {
                reload();
            }

        if (serverObject != null)
            {
                customPanel = serverObject.getCustomPanel();
            }

        return customPanel;
    }

    /**
     * get a list of menu category which is affected
     *
     * @return list of menu categories which is required.
     */
    public String[] getMenuCategoryIDs()
    {
        return new String[]{ ResourcePage.MENU_OBJECT,
                             ResourcePage.MENU_CONTEXT };
    }

    /**
     * get the menu item under each category
     *
     * @param category category name
     * @return list of the menu items for the given category
     */
    public IMenuItem[] getMenuItems(String category)
    {
        if (category.equals(ResourcePage.MENU_OBJECT) ||
            category.equals(ResourcePage.MENU_CONTEXT)) {
            return new IMenuItem[]{ new MenuItemText(MENU_OPEN_SERVER,
                                                     resource.getString("menu", "open"), "",
                                                     enableOpenMenuItem),
                                    /*
                                    new MenuItemText(MENU_CLONE_SERVER,
                                                     resource.getString("menu", "CloneServer"), "",
                                                     enableCloneMenuItem),
                                    */
                                    new MenuItemText(MENU_REMOVE_SERVER,
                                                     resource.getString("menu", "RemoveServer"), "",
                                                     enableRemoveMenuItem), new MenuItemSeparator(),
                                    new MenuItemText(MENU_SET_ACL,
                                                     Framework._resource.getString("menu",
                                                                                   "EditSetACL"), "", enableSetACLMenuItem),
            };
        }
        return null;
    }



    /**
     * perform action for each individual menu item
     *
     * @param viewInstance console instance
     * @param item menu item
     */
    public void actionMenuSelected(IPage viewInstance, IMenuItem item)
    {
        if (item.getID().equals(MENU_SET_ACL))
            {
                PermissionDlg dlg = new PermissionDlg(consoleInfo, topologyDN);
                dlg.show();
                ModalDialogUtil.disposeAndRaise(dlg, viewInstance.getFramework().getJFrame());
            }
        else
            if (item.getID().equals(MENU_OPEN_SERVER))
                {
                    if (serverObject != null)
                        {
                            if (viewInstance instanceof ResourcePage)
                                {
                                    IResourceObject[] selection =
                                        ((ResourcePage) viewInstance).getSelection();
                                    if (serverObject.canRunSelection(selection))
                                        {
                                            run(viewInstance, selection);
                                        }
                                }
                        }
                }
            else
                if (item.getID().equals(MENU_CLONE_SERVER))
                    {
                        // Multiple selection not allowed.
                        if (serverObject != null)
                            {
                                ServerCloneThread thread =
                                    new ServerCloneThread(consoleInfo, resource,
                                                          serverObject, viewInstance);
                                thread.start();
                            }
                    }
                else
                    if (item.getID().equals(MENU_REMOVE_SERVER))
                        {
                            if (serverObject != null) {
                                if (serverObject instanceof IRemovableServerObject) {
                                    // Prompt user for confirmation.
                                    if (JOptionPane.showConfirmDialog(
                                                                      viewInstance.getFramework().getJFrame(),
                                                                      resource.getString(ERROR_PREFIX,
                                                                                         "RemoveInstanceQuestion") + getName() + "?",
                                                                      resource.getString(ERROR_PREFIX,
                                                                                         "RemoveInstanceTitle"),
                                                                      JOptionPane.YES_NO_OPTION) ==
                                        JOptionPane.YES_OPTION) {
                                        ServerRemoveThread thread =
                                            new ServerRemoveThread(consoleInfo,
                                                                   resource, serverObject, viewInstance);
                                        thread.start();
                                    }
                                }
                            }
                        }
    }

    /**
     * get the server object of this server node
     *
     * @return server object
     */
    public IServerObject getServerObject()
    {
        return serverObject;
    }

    /**
     * check whether the server is an admin server.
     *
     * @return true if it is an admin server. false otherwise.
     */
    public boolean isAdminServer()
    {
        String myName = LDAPUtil.flatting( ldapEntry.getAttribute("cn",
                                                                  LDAPUtil.getLDAPAttributeLocale()));
        if (myName == null) {
            Debug.println(
                          "ERROR ServerNode.isAdminServer: could not get cn for " +
                          getDN());
            return false;
        }

        if (myName.indexOf("admin") == -1) {
            return false;
        } else {
            return true;
        }
    }

    /*
     * Need to follow the "seeAlso" attribute of my LDAPEntry.
     * The "nickname" attribute is available in the LDAPEntry
     * of the "seeAlso" attribute of my LDAPEntry.
     */
    protected String getServerNickname()
    {
        String[] nicknames = getProductNicknames();
        if (nicknames == null || nicknames.length == 0) {
            Debug.println("ERROR ServerNode.getServerNickname: could not get product nicknames");
            return null;
        }

        String myName = LDAPUtil.flatting( ldapEntry.getAttribute("cn",
                                                                  LDAPUtil.getLDAPAttributeLocale()));
        myName = myName.toLowerCase();

        for(int i = 0; i < nicknames.length; i++)
            {
                if (myName.startsWith(nicknames[i]))
                    {
                        Debug.println(
                                      "TRACE ServerNode.getServerNickname: nickname = " +
                                      nicknames[i]);
                        return nicknames[i];
                    }
            }
        Debug.println("ERROR ServerNode.getServerNickname: no nickname for " + myName);
        return null;
    }

    /**
     * get the product nicknames from the global parameter location.
     *
     * @return list of product nickname
     */
    protected String[] getProductNicknames()
    {
        // Reuse if possible
        if (nicknameList != null)
            {
                return nicknameList;
            }

        String gpe = "cn=client, ou=admin, ou=Global Preferences,"+
            LDAPUtil.getInstalledSoftwareDN();
        try
            {
                LDAPEntry entry = ldc.read(gpe);
                if (entry == null)
                    {
                        Debug.println("ERROR ServerNode.getProductNicknames: could not get global parameters entry = " + gpe);
                        return null;
                    }
                LDAPAttribute attribute = entry.getAttribute("nsNickname", LDAPUtil.getLDAPAttributeLocale());
                if (attribute == null)
                    {
                        Debug.println("ERROR ServerNode.getProductNicknames: no 'nsNickname' attribute");
                        return null;
                    }
                Vector nicknames = new Vector();
                Enumeration e = attribute.getStringValues();
                String productLine = null;
                String nickname = null;
                int index = 0;
                while (e.hasMoreElements())
                    {
                        productLine = (String) e.nextElement();
                        index = productLine.indexOf(',');
                        if (index == -1)
                            {
                                Debug.println("ERROR ServerNode.getProductNicknames: malformed value (no comma): " + productLine);
                                continue;
                            }
                        nickname = (productLine.substring(0, index)).toLowerCase();
                        nicknames.addElement(nickname);
                    }
                if (nicknames.size() == 0)
                    {
                        return null;
                    }
                nicknameList = new String[nicknames.size()];
                nicknames.copyInto(nicknameList);
                return nicknameList;
            } catch (LDAPException e) {
                Debug.println("ERROR ServerNode.getProductNicknames: " + e);
                return null;
            }
    }


    /**
     * Lookup all servers whose cn starts with this server's nickname (same server types).
     * For each server found, check if it's in the serverObjectsCache.
     * If the server is not in the cache, instantiate a new IServerObject, passing in
     * the ServiceLocator and ConsoleInfo of this server.
     */
    private synchronized CloneTarget[] getCloneTargets()
    {
        String nickname = getServerNickname();
        if (nickname == null)
            {
                Debug.println("ERROR ServerNode.getCloneTargets: nickname is null");
                return null;
            }

        Vector targetServers = new Vector();
        String currentDN = getDN().toLowerCase();
        String productDN = currentDN.substring(currentDN.indexOf(',') + 1);
        String ss40DN = productDN.substring(productDN.indexOf(',') + 1);
        String hostDN = ss40DN.substring(ss40DN.indexOf(',') + 1);
        String ouDN = hostDN.substring(hostDN.indexOf(',') + 1);
        String filter = "(ObjectClass=NetscapeServer)";
        LDAPSearchResults results = null;

        if (LDAPUtil.isVersion4(ldc)) {
            LDAPSortKey key;
            String lang = Locale.getDefault().getLanguage();
            if (lang == null || lang.equals("")) {
                key = new LDAPSortKey("cn", false);
            } else {
                key = new LDAPSortKey("cn", false, lang);
            }
            LDAPSearchConstraints constraints = ldc.getSearchConstraints();
            constraints.setServerControls(new LDAPSortControl(key, false));
        }

        try {
            // limit search to the organizational unit
            results = ldc.search(ouDN, LDAPConnection.SCOPE_SUB, filter,
                                 null, false);
        } catch (LDAPException e) {
            Debug.println(
                          "ERROR ServerNode.getCloneTargets: search for server instances failed: " + e);
            return null;
        }

        if (results == null) {
            Debug.println(
                          "ERROR ServerNode.getCloneTargets: could not get server instances under " +
                          ouDN);
            return null;
        }

        LDAPEntry serverEntry = null;
        LDAPEntry configEntry = null;
        String serverDN = null;
        String configDN = null;
        String serverProductDN = null;
        String serverSS40DN = null;
        String serverSS40CN = null;
        String serverID = null;
        String serverIDSuffix = null;
        String serverHost = null;
        String serverPort = null;
        String serverName = null;
        String serverNickname = "cn=" + nickname.toLowerCase();
        while (results.hasMoreElements()) {
            try {
                serverEntry = results.next();
            } catch (Exception e) {
                // ldap exception
                continue;
            }
            serverDN = serverEntry.getDN().toLowerCase();
            if (serverDN.startsWith(serverNickname) == false) {
                Debug.println(
                              "TRACE ServerNode.getCloneTargets: serverDN " +
                              serverDN + " cannot be a target.");
                Debug.println("    Expected nickname is " + nickname +
                              ". Type mismatch.");
                continue;
            }
            if (serverDN.equals(currentDN)) {
                Debug.println(
                              "TRACE ServerNode.getCloneTargets: skipping self: " +
                              serverDN);
                continue;
            }
            serverID = LDAPUtil.flatting( serverEntry.getAttribute("cn",
                                                                   LDAPUtil.getLDAPAttributeLocale()));
            serverName = LDAPUtil.flatting(
                                           serverEntry.getAttribute("serverProductName",
                                                                    LDAPUtil.getLDAPAttributeLocale()));
            serverHost = LDAPUtil.flatting(
                                           serverEntry.getAttribute("serverhostname",
                                                                    LDAPUtil.getLDAPAttributeLocale()));
            serverProductDN = serverDN.substring(serverDN.indexOf(',') + 1);
            serverSS40DN = serverProductDN.substring(
                                                     serverProductDN.indexOf(',') + 1);
            serverSS40CN =
                serverSS40DN.substring(0, serverSS40DN.indexOf(','));
            if (serverSS40CN.indexOf('(') == -1) {
                serverIDSuffix = null;
            } else {
                int startIndex = serverSS40CN.indexOf('(');
                int endIndex = serverSS40CN.indexOf(')') + 1;
                serverIDSuffix =
                    serverSS40CN.substring(startIndex, endIndex);
            }
            configDN = "cn=configuration," + serverDN;
            try {
                configEntry = ldc.read(configDN);
                serverPort = LDAPUtil.flatting(
                                               configEntry.getAttribute("nsserverport",
                                                                        LDAPUtil.getLDAPAttributeLocale()));
                Debug.println(
                              "TRACE ServerNode.getCloneTargets: adding clone target: " +
                              serverID);
                targetServers.addElement(
                                         new CloneTarget(serverDN, serverID,
                                                         serverIDSuffix, serverHost, serverPort,
                                                         serverName));
            } catch (LDAPException e) {
                Debug.println(
                              "ERROR ServerNode.getCloneTargets: could not read instance DN: " + e);
            }
        }

        if (targetServers.size() == 0) {
            Debug.println("TRACE ServerNode.getCloneTargets: no servers available to clone to.");
            return null;
        }
        CloneTarget[] targetList = new CloneTarget[targetServers.size()];
        targetServers.copyInto(targetList);

        return targetList;
    }


    private String getJARClassName(LDAPConnection ldc, String serverDN) {
        if (ldc == null) {
            Debug.println("ERROR ServerNode.createServerInstance: no LDAPConnection");
            return null;
        }

        String configDN = "cn=configuration," + serverDN;
        try {
            LDAPEntry configEntry = ldc.read(configDN);
            String className = LDAPUtil.flatting(
                                                 configEntry.getAttribute("nsClassname",
                                                                          LDAPUtil.getLDAPAttributeLocale()));
            if (className == null) {
                Debug.println(
                              "ERROR ServerNode.createServerInstance: no 'nsClassname' attribute in " +
                              configDN);
                return null;
            }
            StringTokenizer tok = new StringTokenizer(className, "@");
            tok.nextToken();
            String jar = tok.nextToken(); //className;
            return jar;
        }
        catch (LDAPException e) {
            Debug.println("ERROR ServerNode.createServerInstance: createServerInstance failed");
            Debug.println("    LDAPException: " + e);
            return null;
        }
    }



    /*
     * This routine sets the cloned ConsoleInfo with the Admin Group
     * specific information needed by each Server Instance. This
     * routine is not invoked for the IServerObject associated with
     * this ServerNode object. It is only called when IServerObjects
     * are created for cloning (because the Topology tree node may
     * not have been "expanded" to cause the creation of these instances).
     */
    protected void initializeConsoleInfo(ConsoleInfo ci, String serverDN)
    {
        String adminURL = getInstanceAdminURL(ldc, serverDN);
        if (adminURL == null) {
            Debug.println(
                          "ERROR ServerNode.initializeConsoleInfo: could not set the adminURL for " +
                          serverDN);
        } else {
            ci.setAdminURL(adminURL);
        }

        String adminOS = getInstanceAdminOS(ldc, serverDN);
        if (adminOS == null) {
            Debug.println(
                          "ERROR ServerNode.initializeConsoleInfo: could not set the adminOS for " +
                          serverDN);
        } else {
            ci.setAdminOS(adminOS);
        }
    }

    /**
     * get the admin server URL
     */
    protected String getInstanceAdminURL(LDAPConnection ldc,
                                         String serverDN) {
        String dn=null;
        try {
            String productDN =
                serverDN.substring(serverDN.indexOf(',') + 1);
            String ss40DN = productDN.substring(productDN.indexOf(',') + 1);
            String adminServerDN =
                getServiceLocator().getAdminServer(ss40DN);
            if (adminServerDN == null) {
                Debug.println(
                              "ERROR ServerNode.getInstanceAdminURL: could not get admin server entry = " +
                              ss40DN);
                return null;
            }

            String configDN = "cn=configuration," + adminServerDN;
            LDAPEntry configEntry = ldc.read(dn=configDN);
            if (configEntry == null) {
                Debug.println(
                              "ERROR ServerNode.getInstanceAdminURL: could not get admin server config entry = " +
                              configDN);
                return null;
            }

            String host = LDAPUtil.flatting(
                                            configEntry.getAttribute("nsServerAddress"));
            String port = LDAPUtil.flatting(
                                            configEntry.getAttribute("nsServerport"));
            boolean securityOn = (LDAPUtil.flatting(
                                                    configEntry.getAttribute("nsServersecurity"))).
                equalsIgnoreCase("on");

            /*
             * nsserveraddress might not be defined, which means that the
             * admin server should listen on all interfaces rather than on
             * a specific one. Read serverhostname from the SIE entry.
             * admin server uses 0.0.0.0 to mean listen on all interfaces
             */
            if ((host == null) || (host.trim().length() == 0) || host.equals("0.0.0.0")) {
                LDAPEntry sieEntry = ldc.read(dn=adminServerDN, new String[] {"serverhostname"});
                if (sieEntry == null) {
                    Debug.println(0, "ERROR ConsoleInfo.getInstanceAdminURL: " +
                                  "could not get serverhostname from " + adminServerDN);
                    return null;
                }
                host = LDAPUtil.flatting(sieEntry.getAttribute("serverhostname"));
            }

            String url = "http";
            if (securityOn) {
                url = url + "s";
            }
            url = url + "://" + host + ":" + port + "/";
            return url;
        } catch (LDAPException e) {
            Debug.println("ERROR ServerNode.getInstanceAdminURL: " +
                          "LDAP error " + e + " dn=" + dn);
        }
        return null;
    }

    /**
     * get the admin server OS type
     */
    protected String getInstanceAdminOS(LDAPConnection ldc,
                                        String serverDN) {
        try {
            String productDN =
                serverDN.substring(serverDN.indexOf(',') + 1);
            String ss40DN = productDN.substring(productDN.indexOf(',') + 1);
            String hostDN = ss40DN.substring(ss40DN.indexOf(',') + 1);

            LDAPEntry hostEntry = ldc.read(hostDN);
            if (hostEntry == null) {
                Debug.println(
                              "ERROR ServerNode.getInstanceAdminOS: could not get host entry = " +
                              hostDN);
                return null;
            }

            String osVersion = LDAPUtil.flatting(
                                                 hostEntry.getAttribute("nsOsVersion",
                                                                        LDAPUtil.getLDAPAttributeLocale()));
            return osVersion;
        } catch (LDAPException e) {
            Debug.println(
                          "ERROR ServerNode.getInstanceAdminOS: LDAP error " + e);
        }
        return null;
    }


    // Used to temporarily grab input for JFrame glass pane, which disables
    // user input while a task thread is being run.
    private static KeyAdapter tmpGrabKey = new KeyAdapter() {};
    private static MouseAdapter tmpGrabMouse = new MouseAdapter() {};

    /**
     * Grab or release user input.
     *
     * @param viewInstance  console view
     * @param value         grab user input if true, release if false
     */
    private synchronized void setGrabAllInput(JFrame frame, boolean value) {
        Component glassPane = frame.getGlassPane();
        if (value) {
            glassPane.addKeyListener(tmpGrabKey);
            glassPane.addMouseListener(tmpGrabMouse);
            glassPane.setVisible(true);
        } else {
            glassPane.removeKeyListener(tmpGrabKey);
            glassPane.removeMouseListener(tmpGrabMouse);
            glassPane.setVisible(false);
        }
    }


    /**
     * Display the busy signal. Called from a task thread.
     *
     * @param viewInstance  console view
     * @param isBusy        boolean flag to indicate busy
     * @param status        status text to be displayed
     */
    private synchronized void setBusyIndicator(IPage viewInstance, boolean isBusy, String status)
    {

        setBusyIndicator(viewInstance, isBusy, status,
                         (isBusy ? StatusItemProgress.STATE_BUSY : Integer.valueOf(0)));
    }

    private synchronized void setBusyIndicator(IPage viewInstance, boolean isBusy, String status, Object progress)
    {
        JFrame jframe = (viewInstance != null) ? viewInstance.getFramework().getJFrame() :
            UtilConsoleGlobals.getActivatedFrame();

        if (jframe == null || !(jframe instanceof Framework)) {
            return;
        }
        Framework frame = (Framework)jframe;
        setGrabAllInput(frame, isBusy);
        frame.setBusyCursor(isBusy);
        if (status != null) {
            frame.changeStatusItemState(Framework.STATUS_TEXT, status);
        }
        frame.changeStatusItemState(ResourcePage.STATUS_PROGRESS, progress);
    }

    /**
     * Inform the model that the structure has changed. Called from remove thread.
     *
     * @param viewInstance  console view
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

    /*
     * Lookup the "nsClassname" attribute by searching the
     * configuration node of the serverDN passed in. This routine is
     * used to instantiate the class from initialize() as well as
     * during server configuration cloning.
     */
    synchronized IServerObject createServerInstance(String serverDN, String serverID, boolean createForSelf)
    {
        Debug.println(5, "Instantiate  " + topologyDN);
        IServerObject so = null;
        Object obj = serverObjectsCache.get(serverDN);
        if (obj != null && (obj instanceof IServerObject) == true)
            {
                Debug.println("TRACE ServerNode.createServerInstance: instance already exists: " + serverID);
                so = (IServerObject) obj;
                return so;
            }

        String configDN = "cn=configuration," + serverDN;
        try
            {
                setBusyIndicator(null, true, "", Integer.valueOf(0));
                LDAPEntry configEntry = ldc.read(configDN);
                String className = LDAPUtil.flatting(configEntry.getAttribute("nsClassname", LDAPUtil.getLDAPAttributeLocale()));
                if (className == null)
                    {
                        Debug.println("ERROR ServerNode.createServerInstance: no 'nsClassname' attribute in " + configDN);
                        return null;
                    }

                ConsoleInfo ci = null;
                if (createForSelf == true)
                    {
                        ci = (ConsoleInfo)consoleInfo.clone();
                        if (ci == null)
                            {
                                Debug.println("ERROR ServerNode.createServerInstance: could not clone ConsoleInfo");
                                return null;
                            }
                    }
                else
                    {
                        ci = (ConsoleInfo)
                            (getServiceLocator().getConsoleInfo().clone());
                        if (ci == null)
                            {
                                Debug.println("ERROR ServerNode.createServerInstance: could not clone ConsoleInfo");
                                return null;
                            }
                        // initialize ConsoleInfo with the admin server specific for the server.
                        initializeConsoleInfo(ci, serverDN);
                    }
                ci.setCurrentDN(serverDN);

                String jarName = getJARClassName(ldc, serverDN);
                final boolean isDownloaded = ClassLoaderUtil.isAlreadyDownload(jarName);

                if (!isDownloaded && statusDialog == null)
                    {
                        //String title = resource.getString("ServerNodeStatus", "Title");
                        String description = resource.getString("ServerNodeStatus", "Description");
                        statusDialog = new StatusDialog(parentFrame, serverID, description);
                        statusDialog.setConfirmation(StatusDialog.CONFIRM_STOP);
                        statusDialog.setShowDelay(500);
                        statusDialog.setHideDelay(3000);
                        // statusDialog.setIcon(...); // TODO: need icon for jar download
                    }

                IProgressListener progressListener = new IProgressListener()
                    {
                        String progressTemplate = resource.getString("ServerNodeStatus", "Progress");

                        public void progressUpdate(String jarFilename, int totalBytes, int bytesDone)
                        {
                            int percentDone = 0;
                            if(totalBytes > 0)
                                {
                                    percentDone = (totalBytes == bytesDone) ? 100 : (int)((bytesDone * 100.) / totalBytes);
                                }

                            Object args[] = { jarFilename, Integer.valueOf(bytesDone / 1024) };
                            String progressText = java.text.MessageFormat.format(progressTemplate, args);
                            statusDialog.setProgressText(progressText);
                            statusDialog.setProgressValue(percentDone);
                            //try { Thread.currentThread().sleep(500); } catch (Exception e) {};
                        }
                    };

                Class c = null;

                try
                    {
                        if(!isDownloaded) statusDialog.setVisible(true);
                        //if(testJarLoadFailure)
                        //{
                        //    try { Thread.currentThread().sleep(3000); } catch (Exception e) {};
                        //    testJarLoadFailure = false;
                        //}
                        //else
                        c = ClassLoaderUtil.getClass(ci, className, progressListener);
                        if(!isDownloaded) {
                            statusDialog.setVisible(false);
                        }
                    }
                catch (Exception e)
                    {
                        setBusyIndicator(null, false, "");
                        if(!isDownloaded) {
                            statusDialog.setVisible(false);
                        }
                        JOptionPane.showMessageDialog(parentFrame,
                                                      e.getMessage(),
                                                      resource.getString("error", "ClassLoaderTitle"),
                                                      JOptionPane.ERROR_MESSAGE);
                        return null;
                    }

                setBusyIndicator(null, true, "", Integer.valueOf(0));

                if (c == null)
                    {
                        Debug.println("ERROR ServerNode.createServerInstance: could not get class " + className);
                        return null;
                    }

                try
                    {
                        so = (IServerObject) c.newInstance();
                    }
                catch (Exception e)
                    {
                        Debug.println(0,
                                      "ERROR ServerNode.createServerInstance: could not create " +
                                      className);
                        Debug.println(0, "    Exception: " + e);
                        setBusyIndicator(null, false, "");
                        JOptionPane.showMessageDialog(
                                                      parentFrame,
                                                      java.text.MessageFormat.format(
                                                                                     resource.getString("error", "CreateServerObject"),
                                                                                     new Object[]{serverID}) + "\n" + e.getMessage(),
                                                      resource.getString("error", "ClassLoaderTitle"),
                                                      JOptionPane.ERROR_MESSAGE);
                        return null;
                    }

                if (ci.getAdminURL() == null)
                    {
                        String serevrDN = getDN();
                        String productDN =
                            serverDN.substring(serverDN.indexOf(',') + 1);
                        String admingroupDN =
                            productDN.substring(productDN.indexOf(',') + 1);
                        String ldapAdminServer =
                            getServiceLocator().getAdminServer(admingroupDN);
                        if (ldapAdminServer != null) {
                            String adminURL = AdminGroupNode.findAdminURL(ci,
                                                                          ldapAdminServer);
                            ci.setAdminURL(adminURL);
                        }
                    }
                so.initialize(ci);
                loadResourceEditorExtension(ci, jarName);
                if (so instanceof ResourceObject)
                    {
                        ((ResourceObject) so).setName(serverID);
                    }
                // Save for later use in initialize()
                serverObjectsCache.put(serverDN, so);
                return so;
            }
        catch (LDAPException e)
            {
                Debug.println("ERROR ServerNode.createServerInstance: createServerInstance failed");
                Debug.println("    LDAPException: " + e);
                return null;
            }
        finally
            {
                setBusyIndicator(null, false, null);
            }
    }

    public void loadResourceEditorExtension(ConsoleInfo ci, String jarName) {

        LDAPConnection ldc = ci.getLDAPConnection();
        if (ldc == null) return;

        String ldapLocation = "";
        LDAPSearchConstraints cons;
        LDAPSearchResults result;
        LDAPAttribute attribute;

        try {
            cons = ldc.getSearchConstraints();
            cons.setBatchSize(1);
            // then get the resource editor extension
            ldapLocation = "cn=ResourceEditorExtension,"+
                    LDAPUtil.getAdminGlobalParameterEntry();
            result = ldc.search(ldapLocation,
                    LDAPConnection.SCOPE_ONE, "(Objectclass=nsAdminResourceEditorExtension)",
                    null, false, cons);
            Hashtable hResourceEditorExtension = ResourceEditor.getResourceEditorExtension();
            Hashtable deleteResourceEditorExtension = ResourceEditor.getDeleteResourceEditorExtension();

            if (result != null) {
                while (result.hasMoreElements()) {
                    LDAPEntry ExtensionEntry;
                    try {
                        ExtensionEntry = result.next();
                    } catch (Exception e) {
                        // ldap exception
                        continue;
                    }

                    attribute = ExtensionEntry.getAttribute("cn",
                            LDAPUtil.getLDAPAttributeLocale());
                    Enumeration eValues = attribute.getStringValues();
                    String sCN = "";
                    while (eValues.hasMoreElements()) {
                        sCN = (String) eValues.nextElement(); // Take the first CN
                        break;
                    }

                    attribute =
                            ExtensionEntry.getAttribute("nsClassname",
                            LDAPUtil.getLDAPAttributeLocale());
                    if (attribute != null) {
                        eValues = attribute.getStringValues();

                        Vector vClass = (Vector)hResourceEditorExtension.get(
                                sCN.toLowerCase());
                        if (vClass == null) {
                            vClass = new Vector();
                            hResourceEditorExtension.put(
                                    sCN.toLowerCase(), vClass);
                        }

                        while (eValues.hasMoreElements()) {
                            String sJarClassName =
                                    (String) eValues.nextElement();
                            if (!sJarClassName.endsWith("@"+jarName)) continue;

                            Class c = ClassLoaderUtil.getClass(
                                    ci, sJarClassName);

                            if (c != null) {
                                vClass.addElement(c);
                            }
                        }
                    }

                    attribute =
                            ExtensionEntry.getAttribute("nsDeleteClassname",
                            LDAPUtil.getLDAPAttributeLocale());
                    if (attribute != null) {
                        Enumeration deleteClasses =
                                attribute.getStringValues();

                        Vector deleteClassesVector = (Vector)deleteResourceEditorExtension.get(
                                sCN.toLowerCase());
                        if (deleteClassesVector == null) {
                            deleteClassesVector = new Vector();
                            deleteResourceEditorExtension.put(
                                    sCN.toLowerCase(), deleteClassesVector);
                        }

                        while (deleteClasses.hasMoreElements()) {
                            String jarClassname = (String)
                                    deleteClasses.nextElement();
                            if (!jarClassname.endsWith("@"+jarName)) continue;

                            Class c = ClassLoaderUtil.getClass(
                                    ci, jarClassname);
                            if (c != null) {
                                deleteClassesVector.addElement(c);
                            }
                        }
                    }
                }
            }

        }
        catch (LDAPException e) {
            Debug.println("Console: Cannot open "+ldapLocation);
        }
    }

    /**
     * Inner class for opening a server console in a separate thread.
     */
    class ServerRunThread extends Thread {
        IResourceObject node;
        IPage viewInstance;
        IResourceObject[]selection;

        public ServerRunThread(IResourceObject node,
                               IPage viewInstance, IResourceObject[] selection)
        {
            this.node = node;
            this.viewInstance = viewInstance;
            this.selection = selection;
        }

        public void run() {
            // Catch exception as a defensive measure to prevent the
            // run method from exiting without unsetting the busy
            // indicator which effectively hangs the console.
            try {
                ServerNode.this.setBusyIndicator(viewInstance, true,
                                                 resource.getString("status", "openingServer"));
                node.run(viewInstance, selection);
            } catch (Exception e) {

            }
            finally { ServerNode.this.setBusyIndicator(viewInstance,
                                                       false, "");
            } }
    }


    /**
     * Inner class for removing the server instance in a separate thread.
     */
    class ServerRemoveThread extends Thread
    {
        ConsoleInfo ci;
        ResourceSet resource;
        IResourceObject node;
        IPage viewInstance;

        public ServerRemoveThread(ConsoleInfo ci, ResourceSet resource, IResourceObject node, IPage viewInstance)
        {
            this.ci = ci;
            this.resource = resource;
            this.node = node;
            this.viewInstance = viewInstance;
        }

        public void run()
        {
            // Catch exception as a defensive measure to prevent the
            // run method from exiting without unsetting the busy
            // indicator which effectively hangs the console.
            try {
                ServerNode.this.setBusyIndicator(viewInstance, true,
                                                 resource.getString("status", "removingServer"));
                if (((IRemovableServerObject)serverObject).removeServer()
                    == true) {
                    ServerNode.this.setBusyIndicator(viewInstance,
                                                     false, "");
                    ServerNode.this.setBusyIndicator(viewInstance,
                                                     true, resource.getString("status", "refreshingServer"));
                    serverObjectsCache.remove(ServerNode.this.getDN());
                    Debug.println("TRACE ServerRemoveThread: removed server object from cache");
                    ServerNode.this.reloadModel(viewInstance);
                    ServerNode.this.syncTaskSIEData(ci);
                } else {
                    JOptionPane.showMessageDialog(
                                                  viewInstance.getFramework().getJFrame(),
                                                  resource.getString(ERROR_PREFIX,
                                                                     "FailToRemove") + ServerNode.this.getName(),
                                                  resource.getString(ERROR_PREFIX,
                                                                     "RemoveInstanceTitle"),
                                                  JOptionPane.ERROR_MESSAGE);
                }
            } catch (Exception e) {

            }
            finally { ServerNode.this.setBusyIndicator(viewInstance,
                                                       false, "");
            } }
    }


    /**
     * Inner class for cloning a server instance in a separate thread.
     */
    class ServerCloneThread extends Thread
    {
        ConsoleInfo ci;
        ResourceSet resource;
        IResourceObject node;
        IPage viewInstance;
        JFrame frame;

        public ServerCloneThread(ConsoleInfo ci, ResourceSet resource, IResourceObject node, IPage viewInstance)
        {
            this.ci = ci;
            this.resource = resource;
            this.node = node;
            this.viewInstance = viewInstance;
            this.frame = viewInstance.getFramework().getJFrame();
        }

        public void run() {
            // Catch exception as a defensive measure to prevent the
            // run method from exiting without unsetting the busy
            // indicator which effectively hangs the console.
            try {
                ServerNode.this.setBusyIndicator(viewInstance, true,
                                                 resource.getString("status", "gettingCloneTargets"));
                CloneTarget[] targetList =
                    ServerNode.this.getCloneTargets();
                ServerNode.this.setBusyIndicator(viewInstance, false, "");
                if (targetList == null) {
                    JOptionPane.showMessageDialog(frame,
                                                  resource.getString(ERROR_PREFIX, "CloneError"),
                                                  resource.getString(ERROR_PREFIX,
                                                                     "CloneErrorTitle"),
                                                  JOptionPane.ERROR_MESSAGE);
                    return;
                }
                String[] serverList = new String[targetList.length];
                String[] serverInfo = new String[targetList.length];
                String serverIDSuffix = null;
                for (int j = 0; j < targetList.length; j++) {
                    serverIDSuffix = targetList[j].getServerIDSuffix();
                    CloneTarget target = targetList[j];
                    serverList[j] = target.getServerName() + " (" +
                        target.getServerID() + ":" +
                        target.getServerPort() + ")";
                    if (serverIDSuffix != null) {
                        serverList[j] += " " + serverIDSuffix;
                    }

                    serverInfo[j] = targetList[j].getServerHost() + ":" +
                        targetList[j].getServerPort();
                }
                if (cloneSelection == null) {
                    cloneSelection = new ProductSelectionDialog(frame);
                    if (cloneSelection == null) {
                        Debug.println("ERROR ServerNode.actionMenuSelected: could not create ProductSelectionDialog.");
                        return;
                    }
                }
                cloneSelection.configure(
                                         ProductSelectionDialog.FOR_CLONING);
                cloneSelection.setProductList(serverList, serverInfo);
                cloneSelection.show();
                if (cloneSelection.isCancel()) {
                    Debug.println("TRACE ServerNode.actionMenuSelected: server selection dialog was cancelled.");
                    return;
                }

                int[] selectedServers =
                    cloneSelection.getSelectedIndices();
                if (selectedServers.length == 0) {
                    Debug.println("TRACE ServerNode.actionMenuSelected: no server selected.");
                    return;
                }

                ServerNode.this.setBusyIndicator(viewInstance, true,
                                                 resource.getString("status", "cloningServer"));

                // Note that the servers are cloned one at a time. This
                // permits each server to interact with the user as
                // necessary, i.e., for configuration parameters.
                Object obj = null;
                IServerObject serverHandle = null;
                String referenceDN = ServerNode.this.getDN(); // clone this server object.
                Debug.println(
                              "TRACE ServerNode.actionMenuSelected: referenceDN = " +
                              referenceDN);
                for (int i = 0; i < selectedServers.length; i++) {
                    obj = serverObjectsCache.get(
                                                 targetList[selectedServers[i]].getServerDN());
                    if (obj == null) {
                        serverHandle = createServerInstance (
                                                             targetList[selectedServers[i]].getServerDN(),
                                                             targetList[selectedServers[i]].getServerID(), false);
                        if (serverHandle == null) {
                            JOptionPane.showMessageDialog(frame,
                                                          resource.getString(ERROR_PREFIX,
                                                                             "CannotCreateServerHandle"),
                                                          resource.getString(ERROR_PREFIX,
                                                                             "CannotCreateServerHandleTitle"),
                                                          JOptionPane.ERROR_MESSAGE);
                            continue;
                        }
                    } else {
                        serverHandle = (IServerObject) obj;
                    }
                    serverHandle.cloneFrom(referenceDN);
                }
            } catch (Exception e) {

            }
            finally { ServerNode.this.setBusyIndicator(viewInstance,
                                                       false, "");
            } }
    }

    class ServerLoadFailedPanel extends JPanel implements UIConstants
    {
        ServerLoadFailedPanel(String titleText)
        {
            GridBagLayout g = new GridBagLayout();
            GridBagConstraints c = new GridBagConstraints();
            setLayout(g);

            Border spacingBorder = BorderFactory.createEmptyBorder(VERT_WINDOW_INSET,
                                                                   HORIZ_WINDOW_INSET, VERT_WINDOW_INSET, HORIZ_WINDOW_INSET);
            Border etchedBorder = BorderFactory.createEtchedBorder();
            setBorder( BorderFactory.createCompoundBorder(etchedBorder, spacingBorder));

            //String titleText = resource.getString("ServerNodeError", "retryTitle");
            JLabel titleLabel = new JLabel(titleText);

            titleLabel.setIcon(failedLoadIcon);
            titleLabel.setFont(UIManager.getFont("Title.font"));
            ActionListener l = new ActionListener()
                {
                    public void actionPerformed(ActionEvent e)
                    {
                        _fLoaded = false;
                        reload();
                    }
                };

            String buttonText = resource.getString("ServerNodeError","retryButton");
            JButton retryButton = JButtonFactory.create(buttonText, l, "RETRY");
            JButtonFactory.resize(retryButton);

            JPanel headingPanel = new JPanel(new BorderLayout());
            headingPanel.add(BorderLayout.WEST, titleLabel);
            headingPanel.add(BorderLayout.EAST, retryButton);

            c.gridx = 0;      c.gridy = 0;
            c.gridwidth = 2;  c.gridheight = 1;
            c.weightx = 0.0;    c.weighty = 0.0;
            c.fill = GridBagConstraints.HORIZONTAL;
            c.anchor = GridBagConstraints.NORTH;
            g.setConstraints(headingPanel, c);
            add(headingPanel);

            JSeparator separator = new JSeparator();
            separator.setBorder(BorderFactory.createEmptyBorder(2, 0, 2, 0));
            separator.setMinimumSize(separator.getPreferredSize());
            c.gridx = 0;      c.gridy = 1;
            c.gridwidth = 2;  c.gridheight = 1;
            c.weightx = 1.0;    c.weighty = 0.0;
            c.fill = GridBagConstraints.HORIZONTAL;
            c.anchor = GridBagConstraints.NORTH;
            c.insets = new Insets(COMPONENT_SPACE, 0, DIFFERENT_COMPONENT_SPACE, 0);
            g.setConstraints(separator, c);
            add(separator);

            JLabel errorIcon = new JLabel();
            errorIcon.setIcon(UIManager.getIcon("OptionPane.errorIcon"));
            c.gridx = 0;      c.gridy = 2;
            c.gridwidth = 1;  c.gridheight = 1;
            c.weightx = 0.0;    c.weighty = 0.0;
            c.fill = GridBagConstraints.NONE;
            c.anchor = GridBagConstraints.NORTH;
            c.insets = new Insets(COMPONENT_SPACE, 0, DIFFERENT_COMPONENT_SPACE, 0);
            g.setConstraints(errorIcon, c);
            add(errorIcon);


            String descriptionText = resource.getString("ServerNodeError", "retryDescription");
            JTextArea descriptionArea = new JTextArea();
            descriptionArea.setEditable(false);
            descriptionArea.setOpaque(false);
            descriptionArea.setLineWrap(true);
            descriptionArea.setWrapStyleWord(true);
            descriptionArea.setText(descriptionText);
            c.gridx = 1;      c.gridy = 2;
            c.gridwidth = 1;  c.gridheight = 1;
            c.weightx = 1.0;    c.weighty = 1.0;
            c.fill = GridBagConstraints.BOTH;
            c.anchor = GridBagConstraints.NORTH;
            c.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, DIFFERENT_COMPONENT_SPACE, 0);
            g.setConstraints(descriptionArea, c);
            add(descriptionArea);
        }
    }
}



/**
 * Class used to store necessary information about the
 * clone targets in order to create them if necessary.
 */
class CloneTarget
{
    private String dn;
    private String id;
    private String idSuffix;
    private String host;
    private String port;
    private String name;

    public CloneTarget(String dn, String id, String idSuffix, String host, String port, String name)
    {
        this.dn = dn;
        this.id = id;
        this.idSuffix = idSuffix;
        this.host = host;
        this.port = port;
        this.name = name;
    }

    public String getServerDN()
    {
        return dn;
    }

    public String getServerID()
    {
        return id;
    }

    public String getServerIDSuffix()
    {
        return idSuffix;
    }

    public String getServerHost()
    {
        return host;
    }

    public String getServerPort()
    {
        return port;
    }

    public String getServerName()
    {
        return name;
    }
}
