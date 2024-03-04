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

package com.netscape.management.client.topology.ug;

import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Enumeration;

import javax.swing.JComponent;
import javax.swing.JPanel;

import com.netscape.management.client.CloseVetoException;
import com.netscape.management.client.Framework;
import com.netscape.management.client.IFramework;
import com.netscape.management.client.IPage;
import com.netscape.management.client.IStatusItem;
import com.netscape.management.client.MenuItemCategory;
import com.netscape.management.client.MenuItemSeparator;
import com.netscape.management.client.MenuItemText;
import com.netscape.management.client.ResourcePage;
import com.netscape.management.client.StatusItemProgress;
import com.netscape.management.client.console.Console;
import com.netscape.management.client.console.ConsoleInfo;
import com.netscape.management.client.topology.TopologyInitializer;
import com.netscape.management.client.util.ClassLoaderUtil;
import com.netscape.management.client.util.Debug;
import com.netscape.management.client.util.LDAPUtil;
import com.netscape.management.client.util.ResourceSet;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;


/**
 * UGPage contains the users and groups functionality. It is added to the
 * console framework via the TopologyInitializer.
 *
 * @author  terencek
 * @see TopologyInitializer
 */

public class UGPage extends JPanel implements IPage {

    ResourceSet _resource = new ResourceSet("com.netscape.management.client.topology.topology");
    public static final String MENU_TOOLS = "TOOLS";
    public static final String MENU_USER = "USER";

    private boolean canEditUG = true;

    ConsoleInfo _info;
    IFramework _parent;
    EditUserGroupPane _editUserGroupPane;
    protected boolean _isPageSelected = false;
    MenuItemCategory _toolsMenu;
    MenuItemCategory _userMenu;
    MenuItemSeparator _separator;
    protected StatusItemProgress _statusItemProgress =
            new StatusItemProgress(ResourcePage.STATUS_PROGRESS, 0);

    /**
     * Constructor
     *
     * @param info   global information object
     */
    public UGPage(ConsoleInfo info, boolean canEditUG) {
        _info = (ConsoleInfo) info.clone();
        this.canEditUG = canEditUG;
    }


    /**
      * Initializes this object.
      *
      * @param parent  the parent framework
      */
    public void initialize(IFramework parent) {
        _parent = parent;

        Debug.println(Debug.TYPE_RSPTIME, "Initialize U/G Page ...");

        // only initialize the first time
        setLayout(new BorderLayout());
        _editUserGroupPane = new EditUserGroupPane(_info, this, canEditUG);
        add("Center",_editUserGroupPane);
        createUserMenu();
        _toolsMenu = createToolsMenu();
        parent.addStatusItem(_statusItemProgress, IStatusItem.RIGHT);

        Debug.println(Debug.TYPE_RSPTIME, "U/G Page shown");
    }


    /**
      * Sets the text in the status area near the bottom of the window.
      *
      * @param status  the text to set in the status area
      */
    public void setStatusText(String status) {
        if (isPageSelected()) {
            getFramework().changeStatusItemState(Framework.STATUS_TEXT,
                    status);
        }
    }


    /**
      * Returns the main framework object.
      *
      * @return  the main framework object
      */
    public IFramework getFramework() {
        return _parent;
    }


    /**
      * Returns the title for the page.
      *
      * @return  the title for the page
      */
    public String getPageTitle() {
        return _resource.getString("UGPage","title");
    }


    /**
     * @deprecated not used by Framework
     */
    @Deprecated
    public Object clone() {
        return null;
    }


    /**
      * Returns true if page is currently selected
      *
      * @return  true if page is currently selected; false otherwise
      */
    public boolean isPageSelected() {
        return _isPageSelected;
    }


    /**
      * Called internally when page is selected
      *
      * @param parent  the parent framework
      */
    public void pageSelected(IFramework parent) {
        _isPageSelected = true;
        addMenuItems();
        _editUserGroupPane.setFocus();
        parent.addStatusItem(_statusItemProgress, IStatusItem.RIGHT);
    }


    /**
      * Called internally when page is unselected
      *
      * @param parent  the parent framework
      */
    public void pageUnselected(IFramework parent) {
        setStatusText("");
        removeMenuItems();
        _isPageSelected = false;
        parent.removeStatusItem(_statusItemProgress);
    }


    private void addMenuItems() {
        if (_userMenu != null) {
            _parent.addMenuItem(Framework.MENU_TOP, _userMenu);
        }
        if (_toolsMenu != null) {
            _parent.addMenuItem(Framework.MENU_TOP, _toolsMenu);
        }
    }


    private void removeMenuItems() {
        if (_userMenu != null) {
            _parent.removeMenuItem(_userMenu);
        }
        if (_toolsMenu != null) {
            _parent.removeMenuItem(_toolsMenu);
        }
    }


    /**
      * Notification that the framework window is closing.
      *
      * @param parent  the parent framework
      * @exception CloseVetoException  if there are unsaved changes in the model
      */
    public void actionViewClosing(IFramework parent)
            throws CloseVetoException {
        // There is no model for this page so ignore.
    }

    void createUserMenu() {
        _userMenu = new MenuItemCategory(MENU_USER,
                _resource.getString("menuCategory", "User"));
        JComponent[] items = _editUserGroupPane.getUserMenuItems();
        for (int i=0; i < items.length; i++) {
             _userMenu.add(items[i]);
        }
    }

    public MenuItemCategory createToolsMenu() {
        ConsoleInfo ci = Console.getConsoleInfo();
        LDAPConnection ldc = ci.getLDAPConnection();
        String dn = "cn=UserGroupTools," +
                LDAPUtil.getAdminGlobalParameterEntry();

        MenuItemCategory toolsMenu = new MenuItemCategory(MENU_TOOLS,
                Framework.i18n("menu", "Tools"));

        try {
            LDAPEntry entry = null;
            entry = ldc.read(dn, new String[]{ "nsClassName"});

            if (entry != null) {
                LDAPAttribute attribute = entry.getAttribute("nsClassName");
                if (attribute != null) {
                    Enumeration e = attribute.getStringValues();
                    if (e.hasMoreElements()) {
                        String className = (String) e.nextElement();

                                Class c = ClassLoaderUtil.getClass(
                                        ci, className);
                        if (c == null) {
                            Debug.println("Could not load tool: " +
                                    className);
                                } else
                            try {
                                IUGToolPlugin p = null;
                                p = (IUGToolPlugin) c.newInstance();
                                p.initialize(this, ldc);
                                toolsMenu.add(new toolsMenuItem(p));
                            } catch (Exception exc) {
                                Debug.println(
                                        "Could not create tool class " +
                                        className);
                                        Debug.println(
                                                "    Exception: " + exc);
                                    }
                            }
                        }
                    }
        } catch (LDAPException e) {
            switch (e.getLDAPResultCode()) {
            case LDAPException.NO_SUCH_OBJECT:
                // ignore, because it is optional
                break;

            default:
                Debug.println("Error reading entry: " + dn);
                break;
            }
        }

        if (toolsMenu.getItemCount() <= 0)
            return null;
        else
            return toolsMenu;
    }
}


class toolsMenuItem extends MenuItemText implements ActionListener {
    IUGToolPlugin _tool;

    public toolsMenuItem(IUGToolPlugin tool) {
        super(tool.getName(), tool.getDescription());
        addActionListener(this);
        _tool = tool;
    }

    public void actionPerformed(ActionEvent e) {
        _tool.run();
    }
}
