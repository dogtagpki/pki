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

import java.util.*;
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.text.Document;
import javax.swing.event.*;
import com.netscape.management.client.*;
import com.netscape.management.client.components.*;
import com.netscape.management.client.console.*;
import com.netscape.management.client.ug.*;
import com.netscape.management.client.util.*;
import com.netscape.management.client.util.Debug;
import com.netscape.management.nmclf.*;
import netscape.ldap.*;
import netscape.ldap.util.*;


/**
 * EditUserGroupPane provides the content for the main Users and Groups tab.
 * It provides the main interface for accessing all of the functionality for
 * users and groups management.
 *
 * @author  Terence Kwan (terencek@netscape.com)
 */
public class EditUserGroupPane extends JPanel implements ActionListener,
ListSelectionListener, MouseListener, IRPCallBack {

    private final static String EDIT_ID = "Edit";
    private final static String DELETE_ID = "Delete";
    private final static String CREATE_ID = "Create";
    private final static String CHDIR_ID = "ChDir";
    private final static String SEARCH_ID = "Search";
    private final static String ADVSEARCH_ID = "AdvSearch";
    private final static String CREATEOBJ_PREFIX = "New_";
    private final static String CREATEUSER_ID = CREATEOBJ_PREFIX + "User";
    private final static String CREATEGROUP_ID = CREATEOBJ_PREFIX + "Group";
    private final static String CREATEOU_ID = CREATEOBJ_PREFIX + "OU";
    private final static String CREATEADMIN_ID = CREATEOBJ_PREFIX + "Admin";

    private final static String ADMIN_BASE_DN = 
       "ou=Administrators, ou=TopologyManagement, o=netscapeRoot";
    private final static String ADMIN_GROUP_DN = 
       "cn=Configuration Administrators, ou=Groups, ou=TopologyManagement, o=netscapeRoot";

    static final String ATTR_UNIQUE_MEMBER = "uniquemember";

    private ResourceSet _resource;
    private RemoteImage _userIcon;
    private RemoteImage _groupIcon;
    private RemoteImage _ouIcon;

    private ConsoleInfo _consoleInfo;
    private UGPage _parent;
    private String _uniqueAttribute;
    private ChangeDirectoryDialog _searchDirectoryDialog;
    private OUPickerDialog _ouPicker;

    private String _filter;
    private String _filterAttribute;
    private SearchResultPanel _resultPanel;

    private JTextField _queryField;
    private Document _queryFieldDoc;
    private JButton _searchButton;
    private JButton _advancedSearchButton;
    private JButton _editButton;
    private JButton _deleteButton;
    private JButton _createButton;
    private JButton _helpButton;

    private JPopupMenu _contextMenu;
    // Menu items in the _contextMenu
    private JMenuItem _editMenuItem;
    private JMenuItem _deleteMenuItem;

    // User Menu 
    private JComponent[] _userMenu;
    // Menu items in the _userMenu that can be disabled
    private JMenuItem _userEditMenuItem;
    private JMenuItem _userDeleteMenuItem;

    private boolean _canEditUG = true;


    /**
     * Used to handle the callback from the ResourcePickerDlg to update the
     * status area.
     */
    private ISearchResultCallBack _resultCB = new ISearchResultCallBack() {
                public void update() {
                    EditUserGroupPane.this.setSearchField("");
                    String resultString =
                            EditUserGroupPane.this.getResultCountString();
                    EditUserGroupPane.this.setStatusText(resultString);
                    if (EditUserGroupPane.this.getResultCount() == 0) {
                        _resultPanel.addElement(resultString);
                    }
                }
            };

    /**
     * Used to set the default focus on the search button whenever the query
     * field gains focus. This fulfills an useability requirement where
     * pressing the enter in the query field invokes the search.
     */
    private FocusAdapter _focusAdaptor = new FocusAdapter() {
                public void focusGained(FocusEvent e) {
                    if (e.getComponent() == _queryField) {
                        _searchButton.getRootPane().setDefaultButton(
                                _searchButton);
                    }
                }
                public void focusLost(FocusEvent e) {
                    if (e.getComponent() == _queryField) {
                        _searchButton.getRootPane().setDefaultButton(null);
                    }
                }
            };


    /**
     * Constructor creates the Users and Groups primary screen.
     *
     * @param info   the ConsoleInfo for performing LDAP searches
     * @param parent the handle used for setting status text and cursor feedbacks
     */
    public EditUserGroupPane(ConsoleInfo info, UGPage parent, boolean canEditUG) {
        _consoleInfo = (ConsoleInfo) info.clone(); // Need to clone since LDAP connection info may be changed.
        _parent = parent;
        _canEditUG = canEditUG;
        _uniqueAttribute = ResourceEditor.getUniqueAttribute();

        _resource = new ResourceSet("com.netscape.management.client.topology.topology");
        _userIcon = new RemoteImage("com/netscape/management/nmclf/icons/user24.gif");
        _groupIcon = new RemoteImage("com/netscape/management/nmclf/icons/group24.gif");
        _ouIcon = new RemoteImage("com/netscape/management/nmclf/icons/ou24.gif");

        _ouPicker = null;

        // The following may change the LDAP connection info to last preference.
        _searchDirectoryDialog =
                new ChangeDirectoryDialog(null, _consoleInfo);

        _filter = getFilter();
        _filterAttribute = getFilterAttribute();

        // Create the search buttons
        _searchButton = JButtonFactory.create(_resource.getString("UGPage", "Search"),
                          this, SEARCH_ID);
        _searchButton.setToolTipText(_resource.getString("UGPage", "Search_tt"));
        _advancedSearchButton = JButtonFactory.create(_resource.getString("UGPage", "AdvancedSearch"),
                                                      this, ADVSEARCH_ID);
        _advancedSearchButton.setToolTipText(_resource.getString("UGPage", "AdvancedSearch_tt"));

        // Create the search prompt label
        JLabel searchPrompt = new JLabel(getSearchLabel());

        // Create the search query input field
        _queryField = new JTextField();
        _queryField.addActionListener(this);
        _queryField.addFocusListener(_focusAdaptor);

        searchPrompt.setLabelFor(_queryField);

        // Create the search results panel
        JLabel searchResultsLabel =
                new JLabel(_resource.getString("UGPage", "SearchResults"));
        _resultPanel = new SearchResultPanel(_consoleInfo, this);
        _resultPanel.addListSelectionListener(this);
        _resultPanel.addTableMouseListener(this);

        // Layout everything
        JPanel searchPanel = new JPanel(new GridBagLayout());
        GridBagUtil.constrain(searchPanel, searchPrompt, 0, 0,
                GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                GridBagConstraints.SOUTHWEST,
                GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.VERT_WINDOW_INSET,
                SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);
                //SuiLookAndFeel.VERT_WINDOW_INSET, 0);
        GridBagUtil.constrain(searchPanel, _queryField, 0, 1, 1, 1,
                1.0, 0.0, GridBagConstraints.WEST,
                GridBagConstraints.HORIZONTAL, 0,
                SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);
        GridBagUtil.constrain(searchPanel, _searchButton, 1, 1,
                GridBagConstraints.RELATIVE, 1, 0.0, 0.0,
                GridBagConstraints.EAST, GridBagConstraints.NONE, 0,
                SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0, 0);
        GridBagUtil.constrain(searchPanel, _advancedSearchButton, 2, 1,
                GridBagConstraints.REMAINDER, 1, 0.0, 0.0,
                GridBagConstraints.EAST, GridBagConstraints.NONE, 0,
                SuiLookAndFeel.SEPARATED_COMPONENT_SPACE, 0,
                SuiLookAndFeel.HORIZ_WINDOW_INSET);
        GridBagUtil.constrain(searchPanel, searchResultsLabel, 0, 2,
                GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.SEPARATED_COMPONENT_SPACE,
                SuiLookAndFeel.HORIZ_WINDOW_INSET, 0,
                SuiLookAndFeel.HORIZ_WINDOW_INSET);
        GridBagUtil.constrain(searchPanel, _resultPanel, 0, 3,
                GridBagConstraints.REMAINDER,
                GridBagConstraints.REMAINDER, 1.0, 1.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.BOTH,
                0, SuiLookAndFeel.HORIZ_WINDOW_INSET, 0,
                SuiLookAndFeel.HORIZ_WINDOW_INSET);

        // Create the modify function buttons
        _editButton = JButtonFactory.create(_resource.getString("General","Edit"),
                          this, EDIT_ID);
        _editButton.setToolTipText(_resource.getString("UGPage","edit_tt"));
        _editButton.setEnabled(false);
        _deleteButton = JButtonFactory.create(_resource.getString("General","Delete"),
                          this, DELETE_ID);
        _deleteButton.setToolTipText(_resource.getString("UGPage","delete_tt"));
        _deleteButton.setEnabled(false);

        // Create the JPopupMenu to be displayed during the popup trigger mouse event.
        _editMenuItem = new JMenuItem(_editButton.getText());
        _editMenuItem.setActionCommand(EDIT_ID);
        _editMenuItem.addActionListener(this);
        _editMenuItem.setEnabled(false);
        _deleteMenuItem = new JMenuItem(_deleteButton.getText());
        _deleteMenuItem.setActionCommand(DELETE_ID);
        _deleteMenuItem.addActionListener(this);
        _deleteMenuItem.setEnabled(false);
        _contextMenu = new JPopupMenu();
        _contextMenu.add(_editMenuItem);
        _contextMenu.add(_deleteMenuItem);

        // Create the create function buttons
        JPopupMenu createMenu = new JPopupMenu();
        addCreateMenuItems(createMenu);
        _createButton = new PopupMenuButton(_resource.getString("General", "CreateButton"), createMenu );
        _createButton.setToolTipText(_resource.getString("UGPage", "create_tt"));

        // Create the help buttons
        _helpButton = JButtonFactory.createHelpButton(this);

        // Layout the components
        JLabel blankLabel = new JLabel("");
        JPanel buttonPanel = new JPanel(new GridBagLayout());
        if(_canEditUG)
        {
            GridBagUtil.constrain(buttonPanel, _editButton, 0, 0, 1, 1,
                    0.0, 0.0, GridBagConstraints.WEST, GridBagConstraints.NONE,
                    SuiLookAndFeel.COMPONENT_SPACE,
                    SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);
            GridBagUtil.constrain(buttonPanel, _deleteButton, 1, 0,
                    1, 1, 0.0, 0.0, GridBagConstraints.WEST,
                    GridBagConstraints.NONE, SuiLookAndFeel.COMPONENT_SPACE,
                    SuiLookAndFeel.COMPONENT_SPACE, 0, 0);
            GridBagUtil.constrain(buttonPanel, _createButton, 2, 0, 1, 1,
                    0.0, 0.0, GridBagConstraints.WEST, GridBagConstraints.NONE,
                    SuiLookAndFeel.COMPONENT_SPACE,
                    SuiLookAndFeel.COMPONENT_SPACE, 0, 0);
        }
        GridBagUtil.constrain(buttonPanel, blankLabel, 3, 0, 1, 1, 1.0,
                0.0, GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.SEPARATED_COMPONENT_SPACE, 0, 0);
        GridBagUtil.constrain(buttonPanel, _helpButton, 4, 0,
                GridBagConstraints.REMAINDER,
                GridBagConstraints.REMAINDER, 0.0, 0.0,
                GridBagConstraints.EAST, GridBagConstraints.NONE,
                SuiLookAndFeel.SEPARATED_COMPONENT_SPACE, 0,
                SuiLookAndFeel.VERT_WINDOW_INSET,
                SuiLookAndFeel.HORIZ_WINDOW_INSET);

        // Layout everything
        setLayout(new BorderLayout(0, 0));
        add("Center", searchPanel);
        add("South", buttonPanel);
    }

    /**
     * Init User menu category
     */ 
     void initUserMenu() {
         int count = 0;
         JMenuItem item=null;

         if(_canEditUG)
         {
            _userMenu = new JComponent[5];
         
            _userMenu[count++] = new MenuItemCategory(CREATE_ID,
                _resource.getString("menu", "CreateButton"));

            // Create submenu
            JMenuItem createMenu = (JMenuItem) _userMenu[0];
            addCreateMenuItems(createMenu);
         
            _userMenu[count++] = item = new MenuItemText(EDIT_ID,
                _resource.getString("menu", "Edit"), "");
            item.setActionCommand(EDIT_ID);
            item.addActionListener(this);
            item.setEnabled(false);
            _userEditMenuItem = item;

            _userMenu[count++] = item = new MenuItemText(DELETE_ID,
                _resource.getString("menu", "Delete"), "");
            item.setActionCommand(DELETE_ID);
            item.addActionListener(this);
            item.setEnabled(false);
            _userDeleteMenuItem = item;

            _userMenu[count++] = new JSeparator();
         }
         else
         {
            _userMenu = new JComponent[1];
         }
         _userMenu[count++] = item = new MenuItemText(CHDIR_ID,
             _resource.getString("menu", "ChangeDirectory"), "");
         item.setActionCommand(CHDIR_ID);
         item.addActionListener(this);

     }

     /**
      * Add menu items for the craete button: user, group, ou
      */
     private void addCreateMenuItems(JComponent createMenu) {

         JMenuItem item=null;
         // Do not use mnemonics with the PopupMenuButton
         boolean noShortcuts = (createMenu instanceof JPopupMenu);
         String label = null;
         int idx = -1;
         
 
         label =  _resource.getString("menu", "CreateUser");
         if (noShortcuts) {
             label = removeAmpersand(label);
         }
         createMenu.add(item = new MenuItemText(CREATEUSER_ID, label, "")); 
         item.setActionCommand(CREATEUSER_ID);
         item.addActionListener(this);

         label =  _resource.getString("menu", "CreateGroup");
         if (noShortcuts) {
             label = removeAmpersand(label);
         }
         createMenu.add(item = new MenuItemText(CREATEGROUP_ID, label, "")); 
         item.setActionCommand(CREATEGROUP_ID);
         item.addActionListener(this);

         label =  _resource.getString("menu", "CreateOU");
         if (noShortcuts) {
             label = removeAmpersand(label);
         }
         createMenu.add(item = new MenuItemText(CREATEOU_ID, label, ""));
         item.setActionCommand(CREATEOU_ID);
         item.addActionListener(this);

         createMenu.add(new JSeparator());

         label = _resource.getString("menu", "CreateAdmin");
         if (noShortcuts) {
             label = removeAmpersand(label);
         }
         createMenu.add(item = new MenuItemText(CREATEADMIN_ID, label, ""));
         item.setActionCommand(CREATEADMIN_ID);
         item.addActionListener(this);
     }

     /**
      * A helper method to remove '&' from a label, e.g. &Edit. 
      */
     private String removeAmpersand(String str) {
         int idx = str.indexOf('&');
         if (idx != -1) {
             //StringBuffer sb = new StringBuffer(str);
             //sb.deleteCharAt(idx);  // jdk 1.2
             //return sb.toString();
              return str.substring(0,idx) + str.substring(idx+1);
         }
         return str;
    }
     /**
      * Returns an array of menu items for the User menu
      */
     JComponent[] getUserMenuItems() {
         if (_userMenu == null) {
             initUserMenu();
         }
         return _userMenu;
     }


    /**
      * Returns the directory server string which indicates the current users and groups
      * directory server being used.
      *
      * @return  the search directory string
      */
    public String getSearchDirectory() {
        String protocol;
        LDAPConnection ldc = _consoleInfo.getUserLDAPConnection();
        if (ldc != null && ldc.getSocketFactory() != null) {
            protocol = "ldaps://";
        } else {
            protocol = "ldap://";
        }
        //        return _resource.getString("UGPage", "SearchUserAndGroupIn") + " " +
        //                                   protocol + _consoleInfo.getUserHost() + ":" + _consoleInfo.getUserPort() + "/" + _consoleInfo.getUserBaseDN();
        return _resource.getString("UGPage", "SearchUserAndGroupIn") +
                " " + protocol + _consoleInfo.getUserHost() + ":" +
                _consoleInfo.getUserPort() + "/" +
                _consoleInfo.getUserBaseDN();
    }


    /**
      * Convenience routine which returns whether the console is connected to the
      * directory server.
      *
      * @return  true if connected to the directory server; false otherwise
      */
    private boolean isConnected() {
        try {
            LDAPConnection ldc = _consoleInfo.getUserLDAPConnection();
            if (ldc == null) {
                return false;
            }
            if (ldc.isConnected() == false) {
                ldc.connect(LDAPUtil.LDAP_VERSION,
                        _consoleInfo.getUserHost(),
                        _consoleInfo.getUserPort(),
                        _consoleInfo.getAuthenticationDN(),
                        _consoleInfo.getAuthenticationPassword());
            } else if (!ldc.isAuthenticated()) {
                ldc.authenticate(_consoleInfo.getAuthenticationDN(),
                        _consoleInfo.getAuthenticationPassword());
            }
            return (ldc.isConnected() && ldc.isAuthenticated());
        } catch (LDAPException e) {
            Debug.println(
                    "EditUserGroupPane.isConnectionAvailable: Could not connect to LDAP server: " + e);
            return false;
        }
    }


    /**
      * Convenience routine which displays a cannot continue message to the
      * user because the connection to the directory server is down.
      */
    private void displayCannotContinueMsg() {
        // cannot connect
        JOptionPane.showMessageDialog((Frame)_parent.getFramework(),
                _resource.getString("error","OpCannotContinue") +
                _resource.getString("error","NoConnection"),
                _resource.getString("error","title"),
                JOptionPane.ERROR_MESSAGE);
        ModalDialogUtil.sleep();
    }


    /**
      * Implements the ActionListener interface. Invokes the routines to handle
      * action events for searching, bringing up the advanced search dialog, editing
      * an entry, changing the users and groups directory server, creating a new
      * entry, deleting entries, changing the user's password, and showing help.
      *
      * @param e  the ActionEvent object
      */
    public void actionPerformed(ActionEvent e) {

        if (Debug.timeTraceEnabled()) {
            Debug.println(Debug.TYPE_RSPTIME,
                    "Button \"" + e.getActionCommand() + "\" pressed ...");
        }

        if (e.getSource().equals(_searchButton)) {
            doSearch();
            valueChanged(null);
        } else if (e.getSource().equals(_queryField)) {
            doSearch();
            valueChanged(null);
        } else if (e.getSource().equals(_advancedSearchButton)) {
            setBusyCursor(true);
            ResourcePickerDlg dlg =
                    new ResourcePickerDlg(_consoleInfo, null, _resultPanel);
            dlg.setSearchResultCallBack(_resultCB); // get notified after search
            dlg.enableAdminSearch();
            setBusyCursor(false);
            dlg.show();
            dlg.dispose();
            dlg = null;
            valueChanged(null);

        } else if (e.getActionCommand().equals(EDIT_ID)) { 
            if (isConnected() == false) {
                if (JOptionPane.showConfirmDialog((Frame)_parent.getFramework(),
                        _resource.getString("error", "OpCannotContinue") +
                        _resource.getString("error","ReConnect"),
                        _resource.getString("error","title"),
                        JOptionPane.YES_NO_OPTION) ==
                        JOptionPane.OK_OPTION) {
                    _searchDirectoryDialog.show();
                    if (_searchDirectoryDialog.isCancel()) {
                        return;
                    }
                } else {
                    return;
                }
            }
            editEntry();

        } else if (e.getActionCommand().equals(CHDIR_ID)) {
            _searchDirectoryDialog.show();
            if (_searchDirectoryDialog.isCancel()) {
                return;
            }

        } else if (e.getActionCommand().startsWith(CREATEOBJ_PREFIX)) {
            if (isConnected() == false) {
                if (JOptionPane.showConfirmDialog((Frame)_parent.getFramework(),
                        _resource.getString("error", "OpCannotContinue") +
                        _resource.getString("error","ReConnect"),
                        _resource.getString("error","title"),
                        JOptionPane.YES_NO_OPTION) ==
                        JOptionPane.OK_OPTION) {
                    _searchDirectoryDialog.show();
                    if (_searchDirectoryDialog.isCancel()) {
                        return;
                    }
                } else {
                    return;
                }
            }
            _createButton.setEnabled(false);
            setBusyCursor(true);
            createEntry(e.getActionCommand());
            setBusyCursor(false);
            _createButton.setEnabled(true);

        } else if (e.getActionCommand().equals(DELETE_ID) ||
                e.getSource().equals(_deleteMenuItem)) {
            if (isConnected() == false) {
                if (JOptionPane.showConfirmDialog((Frame)_parent.getFramework(),
                        _resource.getString("error", "OpCannotContinue") +
                        _resource.getString("error","ReConnect"),
                        _resource.getString("error","title"),
                        JOptionPane.YES_NO_OPTION) ==
                        JOptionPane.OK_OPTION) {
                    _searchDirectoryDialog.show();
                    if (_searchDirectoryDialog.isCancel()) {
                        return;
                    }
                } else {
                    return;
                }
            }
            setBusyCursor(true);
            // delete user/group
            deleteEntry();
            setBusyCursor(false);

        } else if (e.getSource().equals(_helpButton)) {
            Help help = new Help(_resource);
            help.contextHelp("topology","ugpanel");
        }
    }


    /**
      * Creates a new entry in the directory server. The objectClassesKey parameter
      * determines which object is created: user, group, or organizational unit.
      * The user is prompted to pick the organizational unit under which to create
      * the new entry. The ResourceEditor with content appropriate for the object
      * to be created will be displayed to complete the creation process.
      *
      */
    private void createEntry(String command) {
        
        String title = null;
        String objectClassesKey = null;
        Icon icon = null;
        String baseDN=null;
        String indexAttribute=null;
        boolean createAdmin = false;

        if (command.equals(CREATEADMIN_ID)) {
            objectClassesKey = ResourceEditor.KEY_NEW_USER_OBJECTCLASSES;
            title = _resource.getString("UGPage","CreateAdmin");
            icon  =  _userIcon;
            baseDN = ADMIN_BASE_DN;
            createAdmin = true;
        }
        if (command.equals(CREATEUSER_ID)) {
            objectClassesKey = ResourceEditor.KEY_NEW_USER_OBJECTCLASSES;
            title = _resource.getString("UGPage","CreateUser");
            icon  =  _userIcon;
        }
        if (command.equals(CREATEGROUP_ID)) {
            objectClassesKey = ResourceEditor.KEY_NEW_GROUP_OBJECTCLASSES;
            title = _resource.getString("UGPage","CreateGroup");
            icon  =  _groupIcon;
        }
        if (command.equals(CREATEOU_ID)) {
            objectClassesKey = ResourceEditor.KEY_NEW_OU_OBJECTCLASSES;
            title = _resource.getString("UGPage","CreateOU");
            icon  =  _ouIcon;
            indexAttribute = "ou";
        }

        if (baseDN == null) {

            // Prompt the user to pick the organizational unit under which to
            // create the new entry. For Administartors, baseDN is well-known
            // and fixed, so this step is skipped.

            if (_ouPicker == null) {
                _ouPicker = new OUPickerDialog(_consoleInfo);
            }
            _ouPicker.show(_consoleInfo);
            if (_ouPicker.isCancel()) {
                ModalDialogUtil.disposeAndRaise(_ouPicker, getJFrame());
                return;
            }
            baseDN = (String)_ouPicker.getSelectedValue();
            ModalDialogUtil.disposeAndRaise(_ouPicker, getJFrame());
        }

        if ((baseDN != null) && (!baseDN.equals(""))) {

            ConsoleInfo newInfo = (ConsoleInfo)_consoleInfo.clone();
            if (createAdmin) {
                // Override User Directory to point to the Configuration Directory
                Debug.println(5,"Create Configuration Administrator");
                newInfo.setUserLDAPConnection(newInfo.getLDAPConnection());
            }

            Vector vObjectClass = new Vector();
            vObjectClass =
                    (Vector) ResourceEditor.getNewObjectClasses().get(
                    objectClassesKey);
            ResourceEditor editor =
                    new ResourceEditor(null, newInfo, vObjectClass,
                        baseDN, _resultPanel);
            if (indexAttribute != null) {
                editor.setIndexAttribute(indexAttribute);
            } 

            TitlePanel titlePanel = new TitlePanel();
            titlePanel.setText(title);
            titlePanel.setIcon(icon);
            editor.setTitlePanel(titlePanel);
            editor.setTitle(title);
            editor.showModal();
            ModalDialogUtil.sleep();

            if (editor.getSaveStatus() == true) {
                LDAPEntry entry = editor.getLDAPEntry();
                if (entry != null) {
                    String name = LDAPUtil.flatting(
                            entry.getAttribute("cn",
                            LDAPUtil.getLDAPAttributeLocale()));
                    if (name == null || name.equals("")) {
                        name = LDAPUtil.flatting( entry.getAttribute("ou",
                                LDAPUtil.getLDAPAttributeLocale()));
                    }

                    if (createAdmin) {
                        // Admin must be in the cn=Configuration Administrators group,
                        // because the group is used in ACIs under o=netscapeRoot
                        addToAdminGroup(entry.getDN());
                    }
                    else {
                       // For admins search field is left blank, because
                       // the search button implies use of user ds, and
                       // the admin is in the config ds
                       setSearchField(name);
                    }

                    setStatusText("");

                }
            }

            ModalDialogUtil.disposeAndRaise(editor, getJFrame());
        }
    }


    /**
     * When a administrator is created in needs to be added to the 
     * cn=Configuration Administartors group. On admin delete, however,
     * the DS automatically removes the admin dn from the group, so no
     * action is required.
     */
     private void addToAdminGroup(String adminDN) {
         try {
             LDAPConnection ldc = _consoleInfo.getLDAPConnection();
             LDAPModification mod = new LDAPModification(LDAPModification.ADD,
                 new LDAPAttribute(ATTR_UNIQUE_MEMBER, adminDN));
             ldc.modify(ADMIN_GROUP_DN, mod);
         }
         catch (Exception e) {
            Debug.println(0, "Failed to add config admin to the admin group " + e);
         }
     }
           
     

    /**
      * Edits an existing entry in the directory server. The last selected entry
      * is passed to the ResourceEditor and displayed to be edited.
      */
     private void editEntry() {
        if(!_canEditUG)
            return;
        
        LDAPEntry entry = _resultPanel.getSelectedItem();

        if (entry == null) {
            return;
        }
        setBusyCursor(true);

        // Change user directory to point to the configuration directory
        // if a configuration administrator is being edited
        ConsoleInfo consoleInfo = _consoleInfo;
        if (isAdminUser(entry.getDN())) {
            Debug.println(5,"Edit Configuration Administrator");
            consoleInfo = (ConsoleInfo) _consoleInfo.clone();
            consoleInfo.setUserLDAPConnection(consoleInfo.getLDAPConnection());
        }

        ResourceEditor editor =
                new ResourceEditor(null, consoleInfo, entry, _resultPanel);
        setBusyCursor(false);
        editor.showModal();
        ModalDialogUtil.sleep();

        if (editor.getSaveStatus() == true) {
            entry = editor.getLDAPEntry();
            if (entry != null) {
                String name = LDAPUtil.flatting( entry.getAttribute("cn",
                        LDAPUtil.getLDAPAttributeLocale()));
                if (name == null || name.equals("")) {
                    name = LDAPUtil.flatting( entry.getAttribute("ou",
                            LDAPUtil.getLDAPAttributeLocale()));
                }
                setSearchField(name);
                setStatusText("");
            }
        }

        ModalDialogUtil.disposeAndRaise(editor, getJFrame());
    }


    /**
      * Displays the popup menu as a result of a right mouse button click in the
      * search results table.
      *
      * @param src  the component which generated the event
      * @param x    the horizontal location to display top left corner of popup
      * @param y    the vertical location to display top left corner of popup
      */
    private void showPopupMenu(Component src, int x, int y) {
        Debug.println(
                "TRACE EditUserGroupPane.showPopupMenu: _contextMenu = " +
                _contextMenu);
        _contextMenu.show(src, x, y);
    }


    /**
      * Convenience routine which determines whether the entry is a user entry.
      *
      * @param entry  LDAP object
      */
    private boolean isUserEntry(LDAPEntry entry) {
        String objectClasses = LDAPUtil.flatting(
                entry.getAttribute("objectclass",
                LDAPUtil.getLDAPAttributeLocale())).toLowerCase();
        if (objectClasses != null &&
                objectClasses.indexOf("person") != -1) {
            return true;
        }
        return false;
    }


    /**
      * Convenience routine which determines whether the entry is a group entry.
      *
      * @param entry  LDAP object
      */
    private boolean isGroupEntry(LDAPEntry entry) {
        String objectClasses = LDAPUtil.flatting(
                entry.getAttribute("objectclass",
                LDAPUtil.getLDAPAttributeLocale())).toLowerCase();
        if (objectClasses != null &&
                objectClasses.indexOf("groupofuniquenames") != -1) {
            return true;
        }
        return false;
    }


    /**
      * Determines whether an entry can be deleted. It is used to invoke a product
      * specific clean up operation before an entry is deleted. If the operation
      * fails, then the object cannot be deleted safely. If the operation succeeds
      * or is not attempted because the product does not have any special delete
      * requirements, then the object can be deleted.
      *
      * @param entry  LDAP object
      */
    private boolean isOkayToDelete(LDAPEntry entry) {
        LDAPAttribute attribute = entry.getAttribute("objectclass");
        Enumeration objectClasses = attribute.getStringValues();

        Hashtable table = (Hashtable)
                ResourceEditor.getDeleteResourceEditorExtension();

        while (objectClasses.hasMoreElements()) {
            String objectClassname = (String) objectClasses.nextElement();
            Vector deleteClassesVector =
                    (Vector) table.get(objectClassname.toLowerCase());
            if (deleteClassesVector != null) {
                Enumeration deleteClasses = deleteClassesVector.elements();
                while (deleteClasses.hasMoreElements()) {
                    String classname = "";
                    try {
                        Class c = (Class) deleteClasses.nextElement();
                        classname = c.getName();
                                Object o = c.newInstance();
                        if (o instanceof IResourceDeleteCallBack) {
                            boolean rc = ((IResourceDeleteCallBack) o).
                                    deleteResource(_consoleInfo,
                                    entry.getDN());
                            if (rc == false) {
                                return false;
                            }
                        } else {
                            Debug.println("TRACE EditUserGroupPane: " +
                                    classname + " is not an instance of IResourceDeleteCallBack.");
                                }
                    } catch (Exception e) {
                        Debug.println(
                                "ERROR EditUserGroupPane: cannot create class: " +
                                classname);
                            }
                        }
                    }
                }
                return true;
            }


            /**
              * Deletes selected entries. Operation can be done on one or more entries.
              * The user is first prompted to confirm the deletion.
              */
    private void deleteEntry() {
        Vector v = _resultPanel.getSelectedEntries();
        int size = v.size();
        if (size == 0) {
            return;
        }

        String prompt;
        if (size == 1) {
            LDAPEntry entry = (LDAPEntry) v.elementAt(0);
            String name = LDAPUtil.flatting( entry.getAttribute("cn",
                    LDAPUtil.getLDAPAttributeLocale()));
            if (name == null || name.equals("")) {
                name = LDAPUtil.flatting( entry.getAttribute("ou",
                        LDAPUtil.getLDAPAttributeLocale()));
            }
            prompt = _resource.getString("UGPage", "ConfirmDelete") + " '" +
                    name + "'?";
        } else {
            prompt = _resource.getString("UGPage", "ConfirmDelete") + " " +
                    _resource.getString("UGPage",
                    "ConfirmDeleteMultiple1") + " " + size + " " +
                    _resource.getString("UGPage",
                    "ConfirmDeleteMultiple2") + "?";
        }

        if (JOptionPane.showConfirmDialog((Frame)_parent.getFramework(), prompt,
                _resource.getString("UGPage", "ConfirmDeleteTitle"),
                JOptionPane.YES_NO_OPTION) == JOptionPane.YES_OPTION) {
            ModalDialogUtil.sleep();
            ModalDialogUtil.raise(getJFrame());
            try {
                if (isConnected() == false) {
                    displayCannotContinueMsg();
                    return;
                }
                Enumeration entries = v.elements();
                LDAPEntry entry;
                Vector deletedEntries = new Vector();
                while (entries.hasMoreElements()) {
                    entry = (LDAPEntry) entries.nextElement();
                    
                    if (isOkayToDelete(entry)) {
                        LDAPConnection ldc = _consoleInfo.getUserLDAPConnection();

                        // Point to the configuration directory if a 
                        // configuration administrator is being edited
                        if (isAdminUser(entry.getDN())) {
                            Debug.println(5, "Delete configuration administrator");
                            ldc =  _consoleInfo.getLDAPConnection();
                        }

                        ldc.delete(entry.getDN());
                        deletedEntries.addElement(entry);
                    }
                }
                _resultPanel.deleteRows(deletedEntries);
                setStatusText("");
            } catch (LDAPException ldapException) {
                //Debug.println("Fail to delete directory entry.");
                JOptionPane.showMessageDialog((Frame)_parent.getFramework(),
                        _resource.getString("UGPage",
                        "DeleteFailed") + ldapException,
                        _resource.getString("UGPage",
                        "DeleteErrorTitle"), JOptionPane.ERROR_MESSAGE);
                ModalDialogUtil.sleep();
                ModalDialogUtil.raise(getJFrame());
            }
        } else {
            ModalDialogUtil.sleep();
            ModalDialogUtil.raise(getJFrame());
        }
    }


    /**
      * Convenience routine which returns the text for the search prompt.
      *
      * @return  the text for the search prompt
      */
    public String getSearchLabel() {
        return _resource.getString("UGPage", "SearchUserAndGroup");
    }


    /**
      * Convenience routine which returns the basic filter for searching
      * users, groups, and organizational units.
      *
      * @return  the basic search filter for users, groups, and org units
      */
    public String getFilter() {
        return "(|(objectclass=person)(objectclass=groupofuniquenames)(objectclass=organizationalunit))";
    }


    /**
      * Convenience routine which returns the unique attribute for the search.
      *
      * @return  the unique attribute for the search
      */
    public String getFilterAttribute() {
        return _uniqueAttribute;
    }


    /**
      * Implements the ListSelectionListener interface. Determines when to
      * enable and disable the three primary edit functions: edit, change
      * password, and delete.
      *
      * @param event  list selection event
      */
    public void valueChanged(ListSelectionEvent event) {
        if(_canEditUG)
        {
            Vector v = _resultPanel.getSelectedEntries();
            int size = v.size();

            // Enable the edit button if only one item has been selected.
            boolean isSingleSelection = (size == 1);
            _editButton.setEnabled(isSingleSelection);
            _editMenuItem.setEnabled(isSingleSelection);
            _userEditMenuItem.setEnabled(isSingleSelection);

            // Enable the change password button if only one item has been selected and
            // the item is a user entry.
            boolean isUser = false;
            if (isSingleSelection) {
                LDAPEntry entry = (LDAPEntry) v.elementAt(0);
                isUser = isUserEntry(entry);
            }

            // Enable the delete button if any number of items has been selected.
            boolean isSelected = (size > 0);
            _deleteButton.setEnabled(isSelected);
            _deleteMenuItem.setEnabled(isSelected);
            _userDeleteMenuItem.setEnabled(isSelected);
        }
    }


    /**
      * Sets the text for the status area (near the bottom of the screen).
      *
      * @param status  text for the status area
      */
    public void setStatusText(String status) {
        if (_parent != null) {
            _parent.setStatusText(status);
        }
    }


    /**
      * Sets the cursor for the JFrame.
      *
      * @param isBusy flag whether busy or normal cursor should be set
      */
    public void setBusyCursor(boolean isBusy) {
        if (_parent != null) {
            ((Framework)_parent.getFramework()).setBusyCursor(isBusy);
        }
    }

    /**
      * Returns the current cursor for the JFrame.
      *
      * @return  current cursor for the JFrame
      */
    public Cursor getCursor() {
        if (_parent != null) {
            return _parent.getFramework().getCursor();
        } else {
            return null;
        }
    }


    /**
      * Returns the JFrame.
      *
      * @return  the JFrame
      */
    public JFrame getJFrame() {
        if (_parent != null) {
            return _parent.getFramework().getJFrame();
        } else {
            return null;
        }
    }


    /**
      * Implements MouseListener. Called when mouse activity occurs in SearchResultPanel.
      * Edits the selection. Double click brings up the entry in the ResourceEditor.
      *
      * @param e  the mouse event
      */
    public void mouseClicked(MouseEvent e) {
        if (e.getClickCount() == 2) {
            if (_resultPanel.rowAtPoint(e.getPoint()) != -1) {
                // On double click
                editEntry();
            }
        }
    }

    /**
      * Implements MouseListener.
      *
      * @param e  the mouse event
      */
    public void mouseEntered(MouseEvent e) {
    }

    /**
      * Implements MouseListener.
      *
      * @param e  the mouse event
      */
    public void mouseExited(MouseEvent e) {
    }

    /**
      * Implements MouseListener. Pops up a menu on right button click if appropriate.
      *
      * @param e  the mouse event
      */
    public void mousePressed(MouseEvent e) {
        if (e.isPopupTrigger()) {
            if (_resultPanel.rowAtPoint(e.getPoint()) != -1 &&
                    _resultPanel.getSelectedItem() != null) {
                showPopupMenu(e.getComponent(), e.getX(), e.getY());
            }
        }
    }

    /**
      * Implements MouseListener. Pops up a menu on right button click if appropriate.
      *
      * @param e  the mouse event
      */
    public void mouseReleased(MouseEvent e) {
        if (e.isPopupTrigger()) {
            if (_resultPanel.rowAtPoint(e.getPoint()) != -1 &&
                    _resultPanel.getSelectedItem() != null) {
                showPopupMenu(e.getComponent(), e.getX(), e.getY());
            }
        }
    }


    /**
      * Perform the search using the filter specified in the type-in field. If the
      * type-in field is empty, than it is the same as search for all (i.e., "*").
      */
    public void doSearch() {
        if (!isConnected()) {
            if (JOptionPane.showConfirmDialog((Frame)_parent.getFramework(),
                    _resource.getString("error","OpCannotContinue") +
                    _resource.getString("error","ReConnect"),
                    _resource.getString("error","title"),
                    JOptionPane.YES_NO_OPTION) ==
                    JOptionPane.OK_OPTION) {
                _searchDirectoryDialog.show();
                if (_searchDirectoryDialog.isCancel()) {
                    return;
                }
            } else {
                return;
            }
        }
        String query = _queryField.getText();
        String queryString;

        if (query == null || query.equals("") || query.equals("*")) {
            queryString = "(|(objectclass=person)(objectclass=groupofuniquenames)(objectclass=organizationalunit))";
        } else {
            if (query.indexOf('*') == -1) {
                query = "*" + query + "*";
            }

            if (_filterAttribute.equals("cn")) {
                queryString =
                        "(|(&(objectclass=person)(cn="+query + "))(&(objectclass=groupofuniquenames)(cn="+
                        query + "))(&(objectclass=organizationalunit)(ou="+
                        query + ")))";
            } else if (_filterAttribute.equals("uid")) {
                // Do not perform the substring search on UID, unless user specifically entered it.
                String origQuery = _queryField.getText();
                queryString =
                        "(|(&(objectclass=person)(cn="+query + "))(&(objectclass=groupofuniquenames)(cn="+
                        query + "))(&(objectclass=organizationalunit)(ou="+
                        query + "))(&(objectclass=person)(uid="+
                        origQuery + ")))";
            } else {
                queryString =
                        "(|(&(objectclass=person)(cn="+query + "))(&(objectclass=groupofuniquenames)(cn="+
                        query + "))(&(objectclass=organizationalunit)(ou="+
                        query + "))(&(objectclass=person)("+
                        _filterAttribute + "="+query + ")))";
            }
        }
        Debug.println("Search: " + queryString);

        _resultPanel.removeAllElements();
        _resultPanel.doSearch(_consoleInfo.getUserLDAPConnection(),
                _consoleInfo.getUserBaseDN(), queryString);

        int count = _resultPanel.getListCount();
        setStatusText(_resource.getString("UGPage","TotalFind") + count);
        if (count == 0) {
            _resultPanel.addElement(
                    _resource.getString("UGPage","TotalFind") + count);
        }
    }



    /**
     * Check if a dn is a configuration admistrator. There is no a special
     * object class for configuration adminstrators (it is of type inetOrgPerson
     * just like regular users) so we check if the dn is contained under
     * ADMIN_BASE_DN
     */
    private boolean isAdminUser(String dn) {
        String[] baseDN = (new DN(ADMIN_BASE_DN)).explodeDN(false);
        String[] objDN  = (new DN(dn)).explodeDN(false);

        if (objDN.length != (baseDN.length + 1)) {
             return false;
        }

        for (int i=0; i < baseDN.length; i++) {
             if (! baseDN[i].equalsIgnoreCase(objDN[i+1])) {
                  return false;
              }
         }

         return true;
     }

    /**
      * Returns the search result count.
      *
      * @return  result count
      */
    public int getResultCount() {
        return _resultPanel.getListCount();
    }


    /**
      * Returns the search result count string useful for displaying status.
      *
      * @return  result count string
      */
    public String getResultCountString() {
        return _resource.getString("UGPage","TotalFind") + getResultCount();
    }


    /**
      * Sets the keyboard focus to the type-in field.
      */
    public void setFocus() {
        _queryField.requestFocus();
    }


    /**
      * Sets the type-in field with the specified query string.
      *
      * @param query  the string to place in the type-in field
      */
    public void setSearchField(String query) {
        if (query != null) {
            _queryField.setText(query);
        }
    }


    /**
      * Implementation for the IRPCallback interface.
      *
      * @param result  the Search results
      */
    public void getResults(Vector result) {
        _resultPanel.removeAllElements();
        Enumeration e = result.elements();
        int iCount = 0;
        while (e.hasMoreElements()) {
            LDAPEntry entry = (LDAPEntry) e.nextElement();
            _resultPanel.addElement(entry);
            iCount++;
        }
        setStatusText(_resource.getString("UGPage","TotalFind") + iCount);
    }
}

