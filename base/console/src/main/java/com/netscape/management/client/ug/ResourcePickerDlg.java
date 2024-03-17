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

package com.netscape.management.client.ug;

import java.awt.CardLayout;
import java.awt.Component;
import java.awt.Container;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ComponentEvent;
import java.awt.event.ComponentListener;
import java.util.Enumeration;
import java.util.Vector;

import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;

import com.netscape.management.client.console.ConsoleInfo;
import com.netscape.management.client.util.AbstractDialog;
import com.netscape.management.client.util.AbstractModalDialog;
import com.netscape.management.client.util.Debug;
import com.netscape.management.client.util.GridBagUtil;
import com.netscape.management.nmclf.SuiLookAndFeel;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;

/**
 * ResourcePickerDlg is a general UI for searching the directory server. By
 * default, it includes two search plugins: basic and advanced. The basic
 * search plugin allows users to search for users, groups, or both by name.
 * The advanced search allows users to search for users, groups, or both
 * matching multiple attributes, such as name, uid, etc.
 *
 * Developers can provide their own search plugins to perform the searches
 * based on their own criteria. For example, searching in other locations
 * such as a web site or some other data store).
 *
 * ResourcePickerDlg displays the results once the search is completed.
 * Users can select the desired entries to be returned, and the selected
 * entries will be sent as the argument to IRPCallBack.getResults().
 */
public class ResourcePickerDlg extends AbstractModalDialog implements ActionListener,
ComponentListener/*, KeyListener*/
{

    private PickerEditorResourceSet resource =
            new PickerEditorResourceSet();

    /**
     * Basic search interface ID
     */
    final public static String BASIC_SEARCH_PANEL = "BASIC";

    /**
     * Advance search interface ID
     */
    final public static String ADVANCE_SEARCH_PANEL = "ADVANCE";

    final private int SEARCH_PANEL = 0;
    final private int RESULT_PANEL = 1;
    final private int PANEL_COUNT = 2;

    final static String ADMIN_BASE_DN =
       "ou=Administrators, ou=TopologyManagement, o=netscapeRoot";

    JPanel _mainPanel; // this will contain plugin component
    CardLayout _mainPanelLayout; // card layout to hold all plugin components

    //default plug panels
    BasicPanel _basicPanel;
    boolean _basicSearchEnabled;
    AdvancePanel _advancedPanel;
    boolean _advancedSearchEnabled;

    ActionPanel _actionPanel;

    SearchResultPanel _searchResultPanel;
    boolean _requireCallback; // Don't need to do the callback if _searchResultPanel was passed in.
    IRPCallBack _callBack = null;

    ResourcePickerDlgMenu _menuBar; // Menu bar

    ConsoleInfo _consoleInfo; // Contains LDAP info used to connect to directory server

    Object _displayedPanel[] = new Object[PANEL_COUNT];
    boolean _shown[] = new boolean[PANEL_COUNT];

    Vector _searchInterface; // Vector of IResourcePickerPlugin

    ISearchResultCallBack _resultCB = null;

    JLabel _baseDNValue;
    boolean _changeDirectoryEnabled = false;
    JFrame _parent;


    /**
     * Constructor for creating the default ResourcePickerDlg with the two
     * search interfaces (basic and advanced) and a search results panel.
     * This dialog has OK | Cancel | Help buttons.
     *
     * @param info    contains all neccssary information required to connect
     *                to the Directory Server
     * @param parent  the parent Frame for this dialog
     */
    public ResourcePickerDlg(ConsoleInfo info, JFrame parent) {
        super(parent);
        _parent = parent;
        initialize(info);
    }


    /**
      * Convenient constructor for creating the default ResourcePickerDlg
      * without providing the parent frame. The dialog will discover the
      * activated Frame automatically and use that as the parent Frame.
      * This dialog has OK | Cancel | Help buttons.
      *
      * @param info  contains all neccssary information required to connect
      *              to the Directory Server
      */
    public ResourcePickerDlg(ConsoleInfo info) {
        super(null);
        _parent = null;
        initialize(info);
    }


    /**
      * Constructor for creating a ResourcePickerDlg without its own search
      * result panel. The search results are placed in the resultPanel that
      * is passed in. The instance of the ResourcePickerDlg created with
      * this constructor does not call IRPCallBack.getResults(), and note
      * that the dialog buttons are Close | Help.
      *
      * @param info         contains all neccssary information required to
      *                     connect to the Directory Server
      * @param parent       the parent Frame for this dialog
      * @param resultPanel  the panel to place the search results in
      */
    public ResourcePickerDlg(ConsoleInfo info, JFrame parent,
            SearchResultPanel resultPanel) {
        super(parent, "", AbstractDialog.CLOSE | AbstractDialog.HELP);
        _parent = parent;
        initialize(info, resultPanel);
    }


    /**
      * Convenient constructor for creating a ResourcePickerDlg without its
      * own search result panel. The parent frame is not needed as the
      * dialog will discover the activated Frame automatically and use that
      * as the parent Frame. The search results are placed in the panel that
      * is passed in. The instance of the ResourcePickerDlg created with
      * this constructor does not call IRPCallBack.getResults(), and note
      * that the dialog buttons are Close | Help.
      *
      * @param info         all neccssary information required to connect to Directory Server
      * @param resultPanel  the panel to place the search results in
      */
    public ResourcePickerDlg(ConsoleInfo info,
            SearchResultPanel resultPanel) {
        super(null, "", AbstractDialog.CLOSE | AbstractDialog.HELP);
        _parent = null;
        initialize(info, resultPanel);
    }


    /**
      * Constructor for creating the default ResourcePickerDlg with a callback
      * object.
      *
      * @param info      contains all neccssary information required to connect
      *                  to the Directory Server
      * @param callBack  the method to invoke when the dialog is OK'ed.
      * @param parent    the parent Frame for this dialog
      */
    public ResourcePickerDlg(ConsoleInfo info, IRPCallBack callBack,
            JFrame parent) {
        super(parent);
        _parent = parent;
        initialize(info);
        _callBack = callBack;
    }

    /**
      * Convenient constructor for creating the default ResourcePickerDlg with
      * a callback object. The parent frame is not needed as the dialog will
      * will discover the activated Frame automatically and use that as the
      * parent Frame.
      *
      * @param info      contains all neccssary information required to connect
      *                  to the Directory Server
      * @param callBack  the method to invoke when the dialog is OK'ed.
      */
    public ResourcePickerDlg(ConsoleInfo info, IRPCallBack callBack) {
        super(null);
        _parent = null;
        initialize(info);
        _callBack = callBack;
    }


    /**
      * Sets the ISearchResultCallBack object. ISearchResultCallBack is used
      * to notify when a search has been completed. IRPCallBack is used to
      * notify when the search results have been selected to be returned.
      *
      * @param cb  the call back object
      */
    public void setSearchResultCallBack(ISearchResultCallBack cb) {
        _resultCB = cb;
    }


    /**
      * Changes the number of result table columns, its corresponding
      * attributes, and its display names.
      *
      * @param  columnAttributes    the attributes displayed in the columns
      * @param  columnDisplayNames  the column header names
      */
    public void setColumnInfo(Vector columnAttributes,
            Vector columnDisplayNames) {
        _searchResultPanel.setColumnInfo(columnAttributes,
                columnDisplayNames);
    }


    /**
      * Gets the maximum number of results that can be retrieved and displayed
      * if using DS 3.x. For DS 4.0 and beyond, virtual list controls obviate
      * the need for this API.
      *
      * @return the maximum number of results allowed
      */
    public int getMaxResults() {
        return _searchResultPanel.getMaxResults();
    }


    /**
      * Sets the maximum number of results that can be retrieved and displayed
      * if using DS 3.x. For DS 4.0 and beyond, virtual list controls obviate
      * the need for this API.
      *
      * @param  maxResults  the maximum number of results allowed
      */
    public void setMaxResults(int maxResults) {
        _searchResultPanel.setMaxResults(maxResults);
    }


    /**
      * @deprecated  Replaced by setBasicSearchEnabled(boolean)
      * @see #setBasicSearchEnabled(boolean)
      */
    @Deprecated
    public void setEnableBasicSearch(boolean value) {
        setBasicSearchEnabled(value);
    }


    /**
      * Enable the search dialog to display the basic search interface
      *
      * @param value  enable the basic search interface if true, disable otherwise
      * @see #setAdvancedSearchEnabled
      */
    public void setBasicSearchEnabled(boolean value) {
        _menuBar.disableSearchInterfaceMenuItem(
                _searchInterface.indexOf(_basicPanel), value);
        _basicSearchEnabled = value;
    }


    /**
      * Enable search of Configuration Administrators
      */
    public void enableAdminSearch() {
        if (_basicPanel != null) {
            _basicPanel.enableAdminSearch();
        }
        if (_advancedPanel != null) {
            _advancedPanel.enableAdminSearch();
        }
    }


    /**
      * Define the search object filter. By default, the basic search already contains:
      * "users" (objectclass=person), "groups" (objectclass=groupofuniquenames) and
      * "users and groups" (|(objclass=person)(objectclass=groupofuniquenames)).
      *
      * @param arFilter  new search filters
      */
    public void setBasicSearchFilter(AttributeSearchFilter arFilter[]) {
        _basicPanel.setDisplayAttribute(arFilter);
    }


    /**
      * @deprecated  Replaced by setAdvancedSearchEnabled(boolean)
      * @see #setAdvancedSearchEnabled(boolean)
      */
    @Deprecated
    public void setEnableAdvanceSearch(boolean value) {
        setAdvancedSearchEnabled(value);
    }


    /**
      * Enable the search dialog to display the advanced search interface
      *
      * @param value  enable the advanced search interface if true, disable otherwise
      * @see #setBasicSearchEnabled
      */
    public void setAdvancedSearchEnabled(boolean value) {
        _menuBar.disableSearchInterfaceMenuItem(
                _searchInterface.indexOf(_advancedPanel), value);
        _advancedSearchEnabled = value;
    }


    /**
      * @deprecated  Replaced by setAttributeSearchFilter(AttributeSearchFilter)
      * @see #setAttributeSearchFilter(AttributeSearchFilter)
      */
    @Deprecated
    public void setAtributeSearchFilter(AttributeSearchFilter arFilter[]) {
        _advancedPanel.setDisplayAttribute(arFilter);
    }


    /**
      * Set the search filter for the advanced search interface. By default,
      * it already contains filter for "username", "lastname", "surename", "telephone", ...
      *
      * @param arFilter Search filter
      */
    public void setAttributeSearchFilter(
            AttributeSearchFilter arFilter[]) {
        _advancedPanel.setDisplayAttribute(arFilter);
    }


    /**
      * Add a search interface plugin
      *
      * @param searchInterface  the new plugin
      */
    public void appendSearchInterface(
            IResourcePickerPlugin searchInterface) {
        _menuBar.addSearchInterfaceMenuItem(
                searchInterface.getDisplayName(),
                searchInterface.getID(), _searchInterface.size());
        _searchInterface.addElement(searchInterface);
        _mainPanel.add(searchInterface.getID(),
                searchInterface.getSearchUI());
        ((Component) searchInterface).addComponentListener(this);
        _actionPanel.updateMethodButtonWidth(
                searchInterface.getDisplayName());
        if (_displayedPanel[SEARCH_PANEL] != null) {
            selectSearchInterface( ((IResourcePickerPlugin)_displayedPanel[
                    SEARCH_PANEL]).getID());
        }
    }


    /**
      * Insert a search interface plugin into specific index
      *
      * @param index            the position to add the plugin
      * @param searchInterface  the new plugin
      * @exception ArrayIndexOutOfBoundsException
      */
    public void insertSearchInterfaceAt(int index,
            IResourcePickerPlugin searchInterface) {
        _menuBar.addSearchInterfaceMenuItem(
                searchInterface.getDisplayName(),
                searchInterface.getID(), _searchInterface.size());
        _searchInterface.insertElementAt(searchInterface, index);
        _mainPanel.add(searchInterface.getID(),
                searchInterface.getSearchUI());
        ((Component) searchInterface).addComponentListener(this);
        _actionPanel.updateMethodButtonWidth(
                searchInterface.getDisplayName());
        if (_displayedPanel[SEARCH_PANEL] != null) {
            selectSearchInterface( ((IResourcePickerPlugin)_displayedPanel[
                    SEARCH_PANEL]).getID());
        }
    }


    /**
      * Delete the specified search interface plugin
      *
      * @param index  the plugin to delete
      * @exception ArrayIndexOutOfBoundsException
      */
    public void deleteSearchInterface(int index) {
        IResourcePickerPlugin pluginToRemove =
                (IResourcePickerPlugin)_searchInterface.elementAt(index);

        // If deleting currently displayed plugin, set the displayable
        // to the next available plugin for refresh
        if (pluginToRemove == _displayedPanel[SEARCH_PANEL]) {
            IResourcePickerPlugin nextPlugin =
                    getNextInterface(pluginToRemove);
            if (nextPlugin == pluginToRemove) {
                _displayedPanel[SEARCH_PANEL] = null;
            } else {
                _displayedPanel[SEARCH_PANEL] = nextPlugin;
            }
        }

        _mainPanel.remove(pluginToRemove.getSearchUI());
        _searchInterface.removeElementAt(index);
        _menuBar.deleteSearchInterfaceMenuItem(index);

        if (_displayedPanel[SEARCH_PANEL] != null) {
            selectSearchInterface( ((IResourcePickerPlugin)_displayedPanel[
                    SEARCH_PANEL]).getID());
        } else {
            // Clear the text.
            _actionPanel.setMethodButtonText("", "");
            updateGUI();
        }
    }


    /**
      * Get all the search interface
      *
      * @return An enumeration of the search interfaces.
      */
    public Enumeration getSearchInterfaces() {
        return _searchInterface.elements();
    }


    /**
      * Select the specified search interface to display
      *
      * @param interfaceID  the search interface to display
      */
    public void selectSearchInterface(String interfaceID) {
        Enumeration searchInterface = getSearchInterfaces();

        String id = "";
        String text = "";
        while (searchInterface.hasMoreElements()) {
            IResourcePickerPlugin searchPanel = (IResourcePickerPlugin)
                    (searchInterface.nextElement());
            if (searchPanel.getID().equals(interfaceID)) {
                _mainPanelLayout.show(_mainPanel, interfaceID);
                _displayedPanel[SEARCH_PANEL] = searchPanel;
                _shown[SEARCH_PANEL] = true;
                // set method button
                searchPanel = getNextInterface(searchPanel);
                if (searchPanel == null) {
                    _actionPanel.setEnableMethod(false);
                } else {
                    id = searchPanel.getID();
                    text = searchPanel.getDisplayName();
                    _actionPanel.setMethodButtonText(id, text);
                }
                updateGUI();
                return;
            }
        }
    }


    /**
      * Get the next available plugin after the specified plugin.
      *
      * @param plugin  the reference plugin
      */
    private IResourcePickerPlugin getNextInterface(
            IResourcePickerPlugin plugin) {
        IResourcePickerPlugin returnValue = null;
        int index = _searchInterface.indexOf(plugin);
        do {
            index++;
            if (index >= _searchInterface.size()) {
                index = 0;
            }
            IResourcePickerPlugin iInterface =
                    (IResourcePickerPlugin)_searchInterface.elementAt(
                    index);
            if (iInterface == plugin) {
                break;
            }
            if ((iInterface == _basicPanel) && (!_basicSearchEnabled)) {
                index++;
                continue;
            } else if ((iInterface == _advancedPanel) &&
                    (!_advancedSearchEnabled)) {
                index++;
                continue;
            }
            returnValue = iInterface;
            break;
        } while (true)
            ;
        return returnValue;
    }


    /**
      * Initializes the default dialog with two search interfaces (basic
      * and advanced), and a search results panel.
      */
    private void initialize(ConsoleInfo info) {
        setTitle(resource.getString("resourcePicker", "Title"));

        _consoleInfo = (ConsoleInfo) info.clone();
        _searchInterface = new Vector();

        // this panel contains the search action button.
        _actionPanel = new ActionPanel(this);
        setDefaultButton(_actionPanel.getSearchButton());

        //menu bar
        _menuBar = new ResourcePickerDlgMenu(this);

        // this panel contains the custom/default search filters.
        _mainPanelLayout = new CardLayout();
        _mainPanel = new JPanel(_mainPanelLayout);

        // add the default basic panel
        _basicPanel = new BasicPanel();
        _basicPanel.setActionPanel(_actionPanel);
        appendSearchInterface(_basicPanel);
        _basicSearchEnabled = true;

        // add the default advanced panel
        _advancedPanel = new AdvancePanel();
        _advancedPanel.setActionPanel(_actionPanel);
        appendSearchInterface(_advancedPanel);
        _advancedSearchEnabled = true;

        // initially display with basic search
        selectSearchInterface(ResourcePickerDlg.BASIC_SEARCH_PANEL);
        setFocusComponent(_basicPanel.getFocusComponent());

        // search result panel
        _searchResultPanel = new SearchResultPanel(_consoleInfo, this);
        _requireCallback = true;
        _displayedPanel[RESULT_PANEL] = _searchResultPanel;
        _shown[RESULT_PANEL] = false;

        // Search host info
        JLabel baseDNLabel = new JLabel(
                resource.getString("resourcePicker","SearchBaseDN"),
                JLabel.RIGHT);
        baseDNLabel.setLabelFor(_baseDNValue);
        _baseDNValue = new JLabel("");
        updateBaseDN();

        // Layout the widgets
        //JPanel p = new JPanel();
        Container p = getContentPane();
        p.setLayout(new GridBagLayout());
        GridBagUtil.constrain(p, baseDNLabel, 0, 0, 1, 1, 0.0, 0.0,
                GridBagConstraints.NORTHWEST,
                GridBagConstraints.HORIZONTAL, 0, 0, 0, 0);
        GridBagUtil.constrain(p, _baseDNValue, 1, 0, 1, 1, 1.0, 0.0,
                GridBagConstraints.NORTHWEST,
                GridBagConstraints.HORIZONTAL, 0,
                SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0, 0);

        GridBagUtil.constrain(p, _actionPanel, 2, 0, 1, 2, 0.0, 0.0,
                GridBagConstraints.NORTHEAST, GridBagConstraints.NONE,
                0, SuiLookAndFeel.SEPARATED_COMPONENT_SPACE, 0, 0);

        GridBagUtil.constrain(p, _mainPanel, 0, 1, 2, 1, 1.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.SEPARATED_COMPONENT_SPACE, 0, 0, 0);

        GridBagUtil.constrain(p, _searchResultPanel, 0, 2,
                GridBagConstraints.REMAINDER,
                GridBagConstraints.REMAINDER, 1.0, 1.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.BOTH,
                SuiLookAndFeel.SEPARATED_COMPONENT_SPACE, 0, 0, 0);

        //setPanel(p);

        setChangeDirectoryEnabled(_changeDirectoryEnabled);
        setMinimumSize(600, 330);
        setSize(600, 330);
    }


    /**
      * Initializes the dialog with only the advanced search interface.
      */
    private void initialize(ConsoleInfo info,
            SearchResultPanel resultPanel) {
        setTitle(resource.getString("resourcePicker", "Title"));

        _consoleInfo = info;
        _searchInterface = new Vector();

        // this panel contains the search action button.
        _actionPanel = new ActionPanel(this);
        setDefaultButton(_actionPanel.getSearchButton());

        //menu bar
        _menuBar = new ResourcePickerDlgMenu(this);

        // this panel contains the custom/default search filters.
        _mainPanelLayout = new CardLayout();
        _mainPanel = new JPanel(_mainPanelLayout);

        // no basic panel needed since called from main u/g tab
        _basicPanel = null;
        _basicSearchEnabled = false;

        // add the default advanced panel
        _advancedPanel = new AdvancePanel();
        _advancedPanel.setActionPanel(_actionPanel);
        appendSearchInterface(_advancedPanel);
        _advancedSearchEnabled = true;

        // display with advanced search
        selectSearchInterface(ResourcePickerDlg.ADVANCE_SEARCH_PANEL);
        setFocusComponent(_advancedPanel.getFocusComponent());

        // Do not create a new SearchResultPanel as part of this dialog.
        // Use the resultPanel passed in.
        _searchResultPanel = resultPanel;
        _requireCallback = false;
        _displayedPanel[RESULT_PANEL] = _searchResultPanel;
        _shown[RESULT_PANEL] = false;

        // Search host info
        JLabel baseDNLabel = new JLabel(
                resource.getString("resourcePicker","SearchBaseDN"),
                JLabel.RIGHT);
        _baseDNValue = new JLabel("");
        baseDNLabel.setLabelFor(_baseDNValue);
        updateBaseDN();

        // Layout the widgets
        //JPanel p = new JPanel();
        Container p = getContentPane();
        p.setLayout(new GridBagLayout());
        GridBagUtil.constrain(p, baseDNLabel, 0, 0, 1, 1, 0.0, 0.0,
                GridBagConstraints.NORTHWEST,
                GridBagConstraints.HORIZONTAL, 0, 0, 0, 0);
        GridBagUtil.constrain(p, _baseDNValue, 1, 0, 1, 1, 1.0, 0.0,
                GridBagConstraints.NORTHWEST,
                GridBagConstraints.HORIZONTAL, 0,
                SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0, 0);

        GridBagUtil.constrain(p, _actionPanel, 2, 0, 1, 2, 0.0, 0.0,
                GridBagConstraints.NORTHEAST, GridBagConstraints.NONE,
                0, SuiLookAndFeel.SEPARATED_COMPONENT_SPACE, 0, 0);

        GridBagUtil.constrain(p, _mainPanel, 0, 1, 2, 1, 1.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.SEPARATED_COMPONENT_SPACE, 0, 0, 0);

        JLabel blankLabel = new JLabel("");
        GridBagUtil.constrain(p, blankLabel, 0, 2,
                GridBagConstraints.REMAINDER,
                GridBagConstraints.REMAINDER, 1.0, 1.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.BOTH,
                SuiLookAndFeel.SEPARATED_COMPONENT_SPACE, 0, 0, 0);

        //setPanel(p);
        /*
        Dimension size = getSize();
        setMinimumSize(size.width, size.height);
        setSize(size.width, size.height);
        */
        setChangeDirectoryEnabled(_changeDirectoryEnabled);
        setMinimumSize(600, 210);
        setSize(600, 210);
    }


    /**
      * Invoke search with the specified filter. If the ISearchResultCallBack
      * object has been set, notify the object that the search has completed.
      */
    private void startSearching() {
        boolean searchAdmin = false;
        setBusyCursor(true);
        _actionPanel.setEnableSearch(false);
        _searchResultPanel.removeAllElements();
        String filter =
                ((IResourcePickerPlugin)_displayedPanel[SEARCH_PANEL]).
                getFilterString();

        if (_displayedPanel[SEARCH_PANEL] instanceof AdvancePanel) {
            AdvancePanel advPanel = (AdvancePanel)_displayedPanel[SEARCH_PANEL];
            searchAdmin = advPanel.getSearchType().equals(AdvancePanel.KEY_ADMINISTRATORS);
        }

        else if (_displayedPanel[SEARCH_PANEL] instanceof BasicPanel) {
            BasicPanel basPanel = (BasicPanel)_displayedPanel[SEARCH_PANEL];
            searchAdmin = basPanel.getSearchType().equals(BasicPanel.KEY_ADMINISTRATORS);
        }

        if (filter != null && filter.equals("") == false) {
            if (searchAdmin) {
                _searchResultPanel.doSearch(
                    _consoleInfo.getLDAPConnection(), // Config dir
                    ADMIN_BASE_DN, filter);
             }
             else {
                _searchResultPanel.doSearch(
                   _consoleInfo.getUserLDAPConnection(), // User dir
                   _consoleInfo.getUserBaseDN(), filter);
             }
        }
        _actionPanel.setEnableSearch(true);
        if (_resultCB != null) {
            _resultCB.update();
        }
        setBusyCursor(false);
    }


    /**
      * Determines whether the LDAPEntry refers to a user entry.
      */
    boolean isUser(LDAPEntry ldapEntry) {
        boolean user = true;
        LDAPAttribute ldapAttribute =
                ldapEntry.getAttributeSet().getAttribute("objectclass");
        Enumeration e = ldapAttribute.getStringValues();
        while (e.hasMoreElements()) {
            if ("groupOfUniqueNames".equalsIgnoreCase(
                    (String)(e.nextElement()))) {
                user = false;
                break;
            }
        }
        return user;
    }


    /**
      * Implements the method to handle ok event. If the IRPCallBack object
      * has been set, notify the object with the selected search results.
      *
      * @see AbstractDialog#okInvoked
      */
    protected void okInvoked() {
        if (_callBack != null && _requireCallback == true) {
            try {
                _callBack.getResults(
                        _searchResultPanel.getSelectedEntries());
            } catch (Exception e) {
                return;
            }
        }
        super.okInvoked();
    }


    /**
      * Implements the method to handle help event.
      *
      * @see AbstractDialog#helpInvoked
      */
    protected void helpInvoked() {
        if (_displayedPanel[SEARCH_PANEL]
                instanceof IResourcePickerPlugin) {
            ((IResourcePickerPlugin)_displayedPanel[SEARCH_PANEL]).help();
        }
    }


    /**
      * Implements the ActionListener interface.
      */
    public void actionPerformed(ActionEvent e) {
        if (e.getActionCommand().startsWith("SHOW:")) {
            selectSearchInterface(e.getActionCommand().substring(5));
            updateGUI();
        } else if (e.getActionCommand().equals("ChangeDir")) {
            ChangeDirectoryDialog cd =
                    new ChangeDirectoryDialog(_parent, _consoleInfo);
            cd.show();
            updateBaseDN();
        } else if (e.getActionCommand().equals("Search")) {
            if (_displayedPanel[SEARCH_PANEL]
                    instanceof IResourcePickerPlugin) {
                startSearching();
            } else if ( _displayedPanel[SEARCH_PANEL]
                    instanceof IAdvancedResPickerPlugin) {
                ((IAdvancedResPickerPlugin)_displayedPanel[SEARCH_PANEL]
                        ).start();
                //to be implimented...
                //need to get result then populate into the result panel
            }

            if (_searchResultPanel.getListCount() > 0) {
                _shown[RESULT_PANEL] = true;
            }
            updateGUI();
        } else {
            Debug.println("ResourcePickerDlg: unhandled option: " +
                    e.getActionCommand());
        }
    }


    /**
      * Sets the call back object for search results that have been selected.
      *
      * @param callBack  the call back object
      */
    public void setCallBack(IRPCallBack callBack) {
        _callBack = callBack;
    }

    public void componentHidden(ComponentEvent e) {}
    public void componentMoved(ComponentEvent e) {}
    public void componentShown(ComponentEvent e) {}
    public void componentResized(ComponentEvent e) {
        if (e.getComponent().equals(_displayedPanel[SEARCH_PANEL])) {
            updateGUI();
        }
    }


    /*
     public void keyTyped(KeyEvent e) {}
     public void keyPressed(KeyEvent e) {}
     public void keyReleased(KeyEvent e) {
     		if (e.getKeyChar()==KeyEvent.VK_ENTER) {
     				actionPerformed(new ActionEvent(this, ActionEvent.ACTION_PERFORMED,"Search"));
     		}
     }
     */


    /**
     * Updates the UI components.
     */
    private void updateGUI() {
        validate();
        repaint();
    }


    /**
      * @deprecated  No replacement. ResourcePickerDlg is a modal dialog.
      */
    @Deprecated
    public boolean showModally() {
        super.show();
        return true;
    }


    /**
      * @deprecated  Replaced by setChangeDirectoryEnabled(boolean)
      * @see #setChangeDirectoryEnabled(boolean)
      */
    @Deprecated
    public void setAllowChangeDirectory(boolean value) {
        setChangeDirectoryEnabled(value);
    }


    /**
      * Enable the button to change the current search directory.
      *
      * @param value  enable the change directory server button if true, disable otherwise
      */
    public void setChangeDirectoryEnabled(boolean value) {
        _changeDirectoryEnabled = value;
        _actionPanel.setAllowChangeDirectory(value);
    }


    /**
      * Updates the search base URL.
      */
    private void updateBaseDN() {
        String protocol;
        LDAPConnection ldc = _consoleInfo.getUserLDAPConnection();
        if (ldc != null && ldc.getSocketFactory() != null) {
            protocol = "ldaps://";
        } else {
            protocol = "ldap://";
        }
        _baseDNValue.setText(protocol + _consoleInfo.getUserHost() + ":"+
                _consoleInfo.getUserPort() + "/"+
                _consoleInfo.getUserBaseDN());
    }
}
