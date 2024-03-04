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
package com.netscape.management.client;

import java.util.*;
import javax.swing.*;
import javax.swing.tree.*;
import com.netscape.management.client.util.*;
import com.netscape.management.client.console.*;
import com.netscape.management.client.ace.*;
import com.netscape.management.client.topology.*;

import com.netscape.management.client.security.CertificateDialog;
import com.netscape.management.client.security.PKCSConfigDialog;
import com.netscape.management.client.security.CertMigrateWizard;
import java.awt.event.*;

import netscape.ldap.*;

/**
  * A type of TaskModel that automatically loads its task list from
  * an LDAP Directory Server.  This TaskModel also populates
  * several commonly used menu items that are used by Netscape Server
  * consoles.
  *
  * @see TaskModel
  * @see IMenuInfo
  */
public class LDAPTaskModel extends TaskModel implements IMenuInfo {
    static public String MENU_OPEN = "OPEN";
    static public String MENU_ACL = "ACL";

    static public String MENU_CERT_DIALOG   = "CERTIFICATE SETUP WIZARD";
    static public String MENU_PKCS11_CONFIG = "CERTIFICATE MANAGEMENT";
    static public String MENU_IMPORT_CERT   = "IMPORT CERTIFICATE";

    static ResourceSet _resource = new ResourceSet("com.netscape.management.client.default");

    protected ITaskObject _selection;
    private boolean canAccessSecurity = false;

    /**
    * Constructs a TaskModel with task entries loaded from ldap
    */
    public LDAPTaskModel(ConsoleInfo ci) {
        super(ci);
        setRoot(getTasksFromLDAP(ci));
        UIPermissions uip = new UIPermissions(LDAPUtil.getAdminGlobalParameterEntry());
        canAccessSecurity = uip.hasPermission(TopologyInitializer.PERMID_SECURITY);
    }

    /**
     * Returns supported menu categories
     */
    public String[] getMenuCategoryIDs() {
        return new String[]{ Framework.MENU_FILE, Framework.MENU_EDIT,
        TaskPage.MENU_CONTEXT };
    }

    /**
     * add menu items for this page.
     */
    public IMenuItem[] getMenuItems(String categoryID) {

        if (categoryID.equals(Framework.MENU_FILE)) {
            if (_consoleInfo.get("CLUSTER") != null) {
                return new IMenuItem[]{ new MenuItemSeparator(),
                new MenuItemText(MENU_OPEN,
                        _resource.getString("menu", "FileOpen"), "TODO:description"), };
            }

            MenuItemText fileopen = new MenuItemText(MENU_OPEN, _resource.getString("menu", "FileOpen"), "TODO:description");
            if(canAccessSecurity)
            {
                MenuItemCategory category = new MenuItemCategory("security", _resource.getString("menu", "FileSecurity"));
                category.add(new MenuItemText(MENU_CERT_DIALOG, _resource.getString("menu", "FileManageCert"), "TODO:description", new SecurityAction(MENU_CERT_DIALOG)));
                category.add(new MenuItemText(MENU_PKCS11_CONFIG, _resource.getString("menu", "FilePKCS11Config"), "TODO:description", new SecurityAction(MENU_PKCS11_CONFIG)));
                category.add(new MenuItemText(MENU_IMPORT_CERT, _resource.getString("menu", "FileImportCert"),  "TODO:description", new SecurityAction(MENU_IMPORT_CERT)));
                return new IMenuItem[] { category, new MenuItemSeparator(), fileopen };
            }
            else
            {
                return new IMenuItem[] { fileopen };
            }
        } else if (categoryID.equals(Framework.MENU_EDIT)) {
            return new IMenuItem[]{ new MenuItemText(MENU_ACL,
                    _resource.getString("menu", "EditSetACL"), "TODO:description",
                    false), };
        } else if (categoryID.equals(TaskPage.MENU_CONTEXT)) {
            return new IMenuItem[]{ new MenuItemText(MENU_OPEN,
                    _resource.getString("menu", "FileOpen"),
                    "TODO:description"),
            new MenuItemText(MENU_ACL,
                    _resource.getString("menu", "EditSetACL"), "TODO:description")};
        }
        return null;
    }

    class SecurityAction implements ActionListener {
        String _id;
        public SecurityAction(String id) {
            _id = id;
        }
        public void actionPerformed(ActionEvent e) {
            if (_id.equals(MENU_CERT_DIALOG)) {
                JFrame f = UtilConsoleGlobals.getActivatedFrame();
                try {
                    if (f != null && f instanceof Framework){
                        ((Framework)f).setBusyCursor(true);
                    }
                    CertificateDialog certDialog = new CertificateDialog(f, _consoleInfo, (String)_consoleInfo.get("SIE"));
                    certDialog.setVisible(true);
                }
                finally {
                    if (f != null && f instanceof Framework){
                        ((Framework)f).setBusyCursor(false);
                    }
                }
            } else if (_id.equals(MENU_PKCS11_CONFIG)) {
                JFrame f = UtilConsoleGlobals.getActivatedFrame();
                try {
                    if (f != null && f instanceof Framework){
                        ((Framework)f).setBusyCursor(true);
                    }
                    PKCSConfigDialog pkcsConfig = new PKCSConfigDialog(f, _consoleInfo, (String)_consoleInfo.get("SIE"));
                    pkcsConfig.setVisible(true);
                }
                finally {
                    if (f != null && f instanceof Framework){
                        ((Framework)f).setBusyCursor(false);
                    }
                }
            } else if (_id.equals(MENU_IMPORT_CERT)) {
                CertMigrateWizard migrateWizard = new CertMigrateWizard(null, _consoleInfo, (String)_consoleInfo.get("SIE"));
                migrateWizard.setVisible(true);
            }
        }
    }

    public void actionObjectSelected(IPage viewInstance,
            ITaskObject selection, ITaskObject previousSelection) {
        super.actionObjectSelected(viewInstance, selection,
                previousSelection);
        _selection = selection;

        if (selection == null)
            fireDisableMenuItem(viewInstance, MENU_ACL);
        else
            fireEnableMenuItem(viewInstance, MENU_ACL);
    }

    /**
       * Notification that a menu item has been selected.
       */
    public void actionMenuSelected(IPage viewInstance, IMenuItem item) {
        if (item.getID().equals(MENU_OPEN)) {
            actionObjectRun(viewInstance, _selection);
        } else if (item.getID().equals(MENU_ACL)) {
            String aclDN = _selection.getConsoleInfo().getCurrentDN();
            JFrame parentFrame = viewInstance.getFramework().getJFrame();
            ACIManager acm = new ACIManager(parentFrame, _selection.getName(), aclDN);
            acm.show();
        }
    }

    /**
     * Returns a list of tasks from the Directory server.  The returned object
     * is the root node for all the tasks.
     */
    public static TaskObject getTasksFromLDAP(ConsoleInfo ci) {
        ResourceSet _resource = new ResourceSet("com.netscape.management.client.default");
        TaskObject root = new TaskObject("root", ci);
        root.setAllowsChildren(true);
        getTasksFromLDAP(ci, root);
        return root;
    }

    /**
     * Creates a list of tasks from the ldap server, adds them to root node.
     */
    public static void getTasksFromLDAP(ConsoleInfo ci,
            DefaultMutableTreeNode root) {
        LDAPSearchResults result = null;
        boolean canAccessSecurity = false;
        try {
            // connect to the DS and search for task information
            LDAPConnection ldc = ci.getLDAPConnection();
            if (ldc != null) {
                UIPermissions uip = new UIPermissions(LDAPUtil.getAdminGlobalParameterEntry());
                canAccessSecurity = uip.hasPermission(TopologyInitializer.PERMID_SECURITY);
                LDAPSearchConstraints cons = ldc.getSearchConstraints();
                cons.setBatchSize(1);
                result = ldc.search(ci.getCurrentDN(),
                        LDAPConnection.SCOPE_SUB, "(ObjectClass=nstask)",
                        null, false, cons);

                while (result.hasMoreElements()) {
                    LDAPEntry findEntry;
                    try {
                        findEntry = (LDAPEntry) result.next();
                    } catch (Exception e) {
                        // ldap exception
                        continue;
                    }
                    // find label
                    LDAPAttributeSet findAttrs =
                            findEntry.getAttributeSet();
                    Enumeration enumAttrs = findAttrs.getAttributes();
                    String sLabel = "";
                    String sJavaClassName = "";
                    String sDescription = "";
                    while (enumAttrs.hasMoreElements()) {
                        LDAPAttribute anAttr =
                                (LDAPAttribute) enumAttrs.nextElement();
                        String attrName = anAttr.getName();
                        if (attrName.equalsIgnoreCase("nsTaskLabel")) {
                            sLabel = LDAPUtil.flatting(
                                    anAttr.getStringValues());
                        } else if (attrName.equalsIgnoreCase("cn")) {
                            // cn =
                        } else if (attrName.equalsIgnoreCase("nsclassname")) {
                            // cn =
                            sJavaClassName = LDAPUtil.flatting(
                                    anAttr.getStringValues());
                        } else if (attrName.equalsIgnoreCase("Description")) {
                            sDescription = LDAPUtil.flatting(
                                    anAttr.getStringValues());
                        }
                    }

                    // DT 6/10/98 If sJavaCLassName is not defined, then don't bother
                    // trying to load the class
                    if (sJavaClassName.equals("")) {
                        Debug.println(
                                "LDAPTaskModel:getTasksFromLDAP:no nsClassName for " +
                                findEntry.getDN());
                        continue;
                    }
                    
                    if (sJavaClassName.indexOf("CertSetup") != -1) 
                    {
                        if(!canAccessSecurity)
                            continue;
                    }

                    // load the associated task class file
                    try {
                        Class c = ClassLoaderUtil.getClass(ci,
                                sJavaClassName);
                        if (c != null) {
                            TaskObject task = (TaskObject) c.newInstance();
                            ConsoleInfo taskConsoleInfo =
                                    (ConsoleInfo) ci.clone();
                            //set SIE string for keycert related tasks
                            taskConsoleInfo.put("SIE", getSIE(ci));
                            taskConsoleInfo.setCurrentDN(
                                    findEntry.getDN());
                            task.setConsoleInfo(taskConsoleInfo);
                            root.add(task);
                        } else {
                            // DT error check for class error
                            System.err.println(
                                    "LdapTaskUtil:getTasksFromLDAP:could not load class for task entry:" +
                                    findEntry.toString());
                        }

                    } catch (Exception e) {
                        Debug.println(
                                "LDAPTaskModel.getTasksFromLdap: Could not load class: " +
                                sJavaClassName + ": Exception: " + e);
                        // This implicitly means that this task should not show up in
                        // in the Task list.
                    }
                }
            }
        }
        catch (Exception e) {
        }
    }

    //parser to extract SIE for KC related tasks
    //after we got task/config window current dn will be
    //the sie it self.  and the first cn will be server-id-host
    static String getSIE(ConsoleInfo consoleInfo) {
        String currentDN = consoleInfo.getCurrentDN();
        return currentDN.substring(currentDN.indexOf("cn=") + 3,
                currentDN.indexOf(","));
    }


    /**
     * Creates a task model that reads task information from LDAP server
     */
    public static ITaskModel createTaskModel(ConsoleInfo ci) {
        return new LDAPTaskModel(ci);
    }
}
