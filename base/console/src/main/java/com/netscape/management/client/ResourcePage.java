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

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import javax.swing.*;
import javax.swing.event.*;
import javax.swing.tree.*;
import javax.swing.border.*;
import com.netscape.management.client.util.*;
import com.netscape.management.client.preferences.*;
import com.netscape.management.nmclf.*;


/**
 * This page view (appears as a tab in Console) displays a tree
 * on the left hand side and a custom panel (for the selected tree node(s))
 * on the the right side.  Data for the tree comes from IResourceModel.
 * The detail panel is a Component returned by IResourceModel::getCustomPanel().
 *
 * @see IPage
 * @see IResourceModel
 * @see IResourceModelListener
 * @see TreeSelectionListener
 */
public class ResourcePage extends JPanel implements IPage,
TreeSelectionListener, MouseListener, KeyListener, TreeWillExpandListener,
IResourceModelListener, Cloneable, SuiConstants {
    public static final String MENU_CONTEXT = "CONTEXT";
    public static final String MENU_OBJECT = "OBJECT";
    public static final String STATUS_PROGRESS = "StatusItemProgress";

    public static final String PREFERENCES_RESOURCES = "ResourcePage";
    public static final String PREFERENCE_SHOW_TREE = "ShowTree";

    // TODO: document these variables and set access modifiers correctly.
    protected IFramework _framework = null;
    protected IResourceModel _model;
    protected JPanel _customPanel = null;
    protected Component _userComponent = null;
    protected JTree _tree = null;
    protected String _pageTitle = "";
    protected JPopupMenu _contextMenu = new JPopupMenu();
    protected IResourceObject[]_previousSelection = null;
    protected TreeCellRenderer _treeRenderer;
    protected JSplitPane _splitPanel;
    protected JScrollPane _treePanel;
    protected MenuInfoAction _menuInfoAction = new MenuInfoAction();
    protected Vector _menuData = new Vector(); // MenuData objects
    protected Vector _statusItems = new Vector(); // IStatusItem objects
    protected Vector _statusItemPositions = new Vector(); // String objects
    protected boolean _isPageSelected = false;
    protected boolean _isTreeVisible = true;
    protected StatusItemProgress _statusItemProgress =
            new StatusItemProgress(STATUS_PROGRESS, 0);

    /**
     * Return ResourcePage using the data model specified.
     */
    public ResourcePage(IResourceModel resourceModel) {
        super();
        _treeRenderer = new ResourceCellRenderer();
        _model = resourceModel;
        _pageTitle = Framework.i18n("page", "Resources");
        setLayout(new BorderLayout());
        _splitPanel = createSplitPanel(resourceModel);
    }

    public void setRootVisible(boolean isRootVisible) {
        _tree.setRootVisible(isRootVisible);
        _tree.setShowsRootHandles(false);
    }

    public void setTreeModel(TreeModel newModel) {
        _tree.setModel(newModel);
    }

    public TreeModel getTreeModel() {
        return _tree.getModel();
    }

    public boolean getRootVisible() {
        return _tree.isRootVisible();
    }

    public void setCellRenderer(TreeCellRenderer renderer) {
        _treeRenderer = renderer;
        if (_tree != null) {
            _tree.setCellRenderer(renderer);

        }
    }

    /**
     *	returns a Component that contains the visuals for this page
     */
    protected JSplitPane createSplitPanel(IResourceModel resourceModel) {
        Component treeComponent = createTree(resourceModel);

        _customPanel = new EmptyPanel();
        _customPanel.setLayout(new BorderLayout());
        _customPanel.setBorder(new EmptyBorder(0, 0, 0, 0));
        _userComponent = new EmptyPanel();
        _customPanel.add(_userComponent);

        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                treeComponent, _customPanel);
        splitPane.setBorder(
                new EmptyBorder(COMPONENT_SPACE, COMPONENT_SPACE,
                COMPONENT_SPACE, COMPONENT_SPACE));
        splitPane.setDividerLocation((int)treeComponent.getPreferredSize().getWidth());
        return splitPane;
    }


    class TreeFocusListener implements FocusListener {
        // this causes ALL tree nodes to repaint, which
        // is need to change colors for selected tree nodes
        public void focusGained(FocusEvent e) {
            JTree tree = (JTree) e.getSource();
            tree.validate();
            tree.repaint();
        }

        public void focusLost(FocusEvent e) {
            JTree tree = (JTree) e.getSource();
            tree.validate();
            tree.repaint();
        }
    }

    /**
     *	returns a Component that contains the tree
     */
    protected Component createTree(IResourceModel resourceModel) {
        _tree = new JTree(resourceModel);
        _tree.addFocusListener(new TreeFocusListener());
        _tree.setCellRenderer(_treeRenderer);
        _tree.addTreeSelectionListener(this);
        _tree.addMouseListener(this);
        _tree.addKeyListener(this);
        _tree.addTreeWillExpandListener(this);

        _treePanel = new JScrollPane();
        _treePanel.getViewport().add(_tree);
        _treePanel.setBorder( new BevelBorder(BevelBorder.LOWERED,
                UIManager.getColor("controlHighlight"),
                UIManager.getColor("control"),
                UIManager.getColor("controlDkShadow"),
                UIManager.getColor("controlShadow")));
        _treePanel.setPreferredSize(new Dimension(200, 200));
        _treePanel.setMinimumSize(new Dimension(1, 1));
        return _treePanel;
    }


    /**
     *	Return exact copy of this page, maintaining state info.
     *  Called by IFramework when user selects File->New Window.
     */
    public Object clone() {
        ResourcePage rp = new ResourcePage(_model);
        return rp;

        /*		TODO: figure out why clone fails
        		try
        		{
        			return (IPage)this.clone();
        		}
        		catch(CloneNotSupportedException e)
        		{
        			Debug.println("ResourcePage.clone: Could not clone");
        		}
        		return (IPage)null;
        */
    }

    /**
     *	Return data model
     */
    public IResourceModel getModel() {
        return _model;
    }

    /**
     *	Return page title.  The title shows up in Framework's tabbed pane,
     *  and also in the menu bars.
     */
    public String getPageTitle() {
        return _pageTitle;
    }

    /**
     *	Sets the page title.
     */
    public void setPageTitle(String title) {
        _pageTitle = title;
    }

    /**
     *	Initializes page.  Called after construction or after clone().
     *  The reference to IFramework allows this page to set menu items, status
     *  bars, and add event notification listeners.
     */
    public void initialize(IFramework framework) {
        PreferenceManager pm = PreferenceManager.getPreferenceManager(
                Framework.IDENTIFIER, Framework.MAJOR_VERSION);
        Preferences p = pm.getPreferences(PREFERENCES_RESOURCES);
        setMainPanel(p.getBoolean(PREFERENCE_SHOW_TREE, true));

        _framework = framework;
        _model.addIResourceModelListener(this);

        // Miodrag 01-19. Selecting the first row is moved to pageSelected(), so
        // the first row is selected the first time page gets visible. This is bacause
        // selecting a row might trigger loading on data from the server. In addition,
        // multiple pages with such behavior might be stacked together. We do not want
        // to have such concurrent loading of data with possible error messages unless
        // the page tab is selected.
        //if (_tree.getComponentCount() > 0)
        //{
        //	// Select the first object.
        //	_tree.setSelectionRow(0);
        //}

        MenuItemCategory objectMenu = new MenuItemCategory(MENU_OBJECT,
                Framework.i18n("menu", "Object"));
        addMenuItem(Framework.MENU_TOP, objectMenu);
        addMenuItem(Framework.MENU_VIEW,
                new MenuItemCheckBox(
                Framework.i18n("menu", "ViewToggleTree"), "TODO:description",
                new TreeToggleAction(), _isTreeVisible));
        if (_model instanceof IMenuInfo)
            addMenuItems((IMenuInfo)_model, _menuInfoAction);
        addStatusItem(_statusItemProgress, IStatusItem.RIGHT);
    }

    /**
     *	Returns the framework in which this page is this displayed.
     *	Implementation: return parent parameter in initialize(...)
     */
    public IFramework getFramework() {
        return _framework;
    }

    /**
     * Sets component to be displayed in right-hand pane.
     * Called internally after a selection is made.
     */
    public void setCustomPanel(Component c) {
        if (_customPanel != null) {
            // optimization: if same as before, don't replace it.
            // used when different objects return same instance of a panel (e.g., table)
            if ((c != null) && (c.equals(_userComponent)))
                return;

            _customPanel.remove(_userComponent);
            if (c != null) {
                _userComponent = c;
            } else {
                if (_userComponent instanceof EmptyPanel)// optimization: already have empty panel

                    return;

                _userComponent = new EmptyPanel();
            }
            _customPanel.add(_userComponent);
            _customPanel.validate();
            _customPanel.repaint();
        }
    }

    class EmptyPanel extends JPanel {
    }

    /**
     * Returns array of selected IResourceObjects.
     */
    public IResourceObject[] getSelection() {
        IResourceObject[] selection = null;
        TreePath path[] = _tree.getSelectionPaths();
        if ((path != null) && (path.length > 0)) {
            selection = new IResourceObject[path.length];
            for (int index = 0; index < path.length; index++) {
                selection[index] = (IResourceObject) path[index]
                        .getLastPathComponent();
            }
        }
        return selection;
    }

    /**
     * Returns array of previously selected IResourceObjects.
     */
    public IResourceObject[] getPreviousSelection() {
        return _previousSelection;
    }

    /**
     * Implements TreeSelectionListener.  Called when an object is selected
     * in the resource tree.  Informs IResourceModelListeners of this event.
     */
    public void valueChanged(TreeSelectionEvent ev) {
        IResourceObject[] selection = getSelection();
        if (selection != null) {
            if (selection.length == 1)// single selection
            {
                setCustomPanel(_model.getCustomPanel(this, selection[0]));
            } else // multiple selection  TODO: determine proper behavior
            {
            }
        }
        _model.actionObjectSelected(this, selection,
                getPreviousSelection());
        _previousSelection = selection;
    }

    /**
     * Implements MouseListener.  Called when mouse activity occurs in resource
     * tree.  Informs model of run().
     */
    public void mouseClicked(MouseEvent e) {
        IResourceObject[] selection = getSelection();
        if (selection != null) {
            if (e.getClickCount() == 2)// double click
            {
                if (selection.length == 1)// single selection
                {
                    if (!_model.isLeaf(selection[0]))
                        return;
                }


                _model.actionObjectRun(this, selection);
            }
        }
    }

    /**
     * Called after run is complete (for each listener).  ranObject specifies
     * which object elected to run.  If no object ran, the value is null.
     * Override this method to display error/success dialogs, etc.
     */
    public void runComplete(IResourceObject ranObject) {
    }

    /**
     * Implements MouseListener.
     */
    public void mousePressed(MouseEvent e) {
        if ((_contextMenu != null) && (e.isPopupTrigger())) {
            if (_contextMenu.getComponentCount() > 0) {
                Point p = _treePanel.getViewport().getViewPosition();
                _contextMenu.show(_treePanel, e.getX() - p.x,
                        e.getY() - p.y);
            }
        }
    }

    /**
     * Implements MouseListener.
     */
    public void mouseEntered(MouseEvent e) {
    }

    /**
     * Implements MouseListener.
     */
    public void mouseExited(MouseEvent e) {
    }

    /**
     * Implements MouseListener.
     */
    public void mouseReleased(MouseEvent e) {
        if ((_contextMenu != null) && (e.isPopupTrigger())) {
            if (_contextMenu.getComponentCount() > 0) {
                Point p = _treePanel.getViewport().getViewPosition();
                _contextMenu.show(_treePanel, e.getX() - p.x,
                        e.getY() - p.y);
            }
        }
    }

    /**
     * Checks to see if the event is intended for this page.
     */
    private boolean isEventTarget(ResourceModelEvent e) {
        IPage targetPage = e.getViewInstance();
        if (targetPage == null)
            return true;

        if (targetPage == this)
            return true;

        return false;
    }

    /**
     * Implements TreeWillExpandListener. Called when a node is about to be
     * expanded.
     * 
     * Gives a chance to load a node before JTree.paint() method is called.
     * If a node is not preloaded in this manner, it will get loaded in the
     * middle of the JTree.paint() method. That might cause UI problems if
     * loading of the node is a time consuming operation or it involves popping
     * up confirmation dialogs. (bug 389955)
     * *
     * @exception ExpandVetoException prevents node expansion if the node
     * could not be loaded
     */
    public void treeWillExpand(TreeExpansionEvent e) throws ExpandVetoException {
         TreeNode node = (TreeNode) e.getPath().getLastPathComponent();
         try {
             // This will force loading of node
             int cnt = node.getChildCount();
             if (cnt < 0) {
                 throw new ExpandVetoException(e);
             }
         } 
         catch (Exception ex) {
             Debug.println(0, "ResourcePage.treeWillExpand " + ex);
             throw new ExpandVetoException(e);
         }
    }

    /**
     * Implements TreeWillExpandListener. Called when a node is about to be
     * collapsed.
     */
    public void treeWillCollapse(TreeExpansionEvent e) throws ExpandVetoException {
    }

    /**
     * Use when menu items have been added.
     * Called by ResourceModel
     * Implements IResourceModelListener
     */
    public void addMenuItems(ResourceModelEvent e) {
        if (isEventTarget(e)) {
            addMenuItems(e.getMenuInfo(), _menuInfoAction);
        }
    }

    /**
     * Use when menu items have been added.
     * Called by ResourceModel
     * Implements IResourceModelListener
     */
    public void enableMenuItem(ResourceModelEvent e) {
        if (isEventTarget(e)) {
            MenuData.enableMenuItem(_menuData, e.getMenuID(), true);
        }
    }

    /**
     * Use when menu items have been added.
     * Called by ResourceModel
     * Implements IResourceModelListener
     */
    public void disableMenuItem(ResourceModelEvent e) {
        if (isEventTarget(e)) {
            MenuData.enableMenuItem(_menuData, e.getMenuID(), false);
        }
    }

    /**
     * Use when menu items have been added.
     * Called by ResourceModel
     * Implements IResourceModelListener
     */
    protected void addMenuItem(String categoryID, IMenuItem menuItem) {
        MenuData menuData =
                new MenuData(categoryID, menuItem, (IMenuInfo) null);
        populateMenuItems(menuData);
        _menuData.addElement(menuData);
    }

    /**
     */
    private void populateMenuItems(MenuData menuData) {
        if (isPageSelected()) {
            if (menuData.getCategoryID().equals(MENU_CONTEXT)) {
                _contextMenu.add(menuData.getIMenuItem().getComponent());
            } else {
                JMenu menu = MenuData.getMenu(_contextMenu,
                        menuData.getCategoryID());
                if (menu != null) {
                    menu.add(menuData.getIMenuItem().getComponent());
                } else {
                    _framework.addMenuItem(menuData.getCategoryID(),
                            menuData.getIMenuItem());
                }
            }
        }
    }


    /**
     */
    private void populateMenuItems(Vector menuDataVector) {
        Enumeration e = menuDataVector.elements();
        while (e.hasMoreElements()) {
            populateMenuItems((MenuData) e.nextElement());
        }
    }

    /**
     */
    private void unpopulateMenuItems(Vector menuDataVector) {
        if (isPageSelected()) {
            for (int i = menuDataVector.size() - 1; i >= 0; i--) {
                MenuData menuData = (MenuData) menuDataVector.elementAt(i);
                if (menuData.getCategoryID().equals(MENU_CONTEXT)) {
                    _contextMenu.remove(
                            menuData.getIMenuItem().getComponent());
                } else {
                    JMenu menu = MenuData.getMenu(_contextMenu,
                            menuData.getCategoryID());
                    if (menu != null) {
                        MenuData.removeMenuItem(menu,
                                menuData.getIMenuItem());
                    } else {
                        _framework.removeMenuItem(menuData.getIMenuItem());
                    }
                }
            }
        }
    }

    /**
     * Use when menu items have been added.
     * Called by ResourceModel
     * Implements IResourceModelListener
     */
    protected void addMenuItems(IMenuInfo menuInfo,
            ActionListener menuActionListener) {
        Vector menuData =
                MenuData.createMenuData(menuInfo, menuActionListener);
        populateMenuItems(menuData);
        MenuData.addVectors(_menuData, menuData);
    }

    /**
     * Removes menu items.
     * Called by ResourceModel
     * Implements IResourceModelListener
     */
    public void removeMenuItems(ResourceModelEvent e) {
        if (isEventTarget(e)) {
            Vector menuData = MenuData.createMenuDataByID(_menuData,
                    MenuData.createMenuData(e.getMenuInfo(),
                    (ActionListener) null));
            unpopulateMenuItems(menuData);
            MenuData.substractVectors(_menuData, menuData);
        }
    }

    /**
     * adds status item to a list of status items managed by this page
     * Called internally
     * Implements IResourceModelListener
     */
    private void addStatusItem(IStatusItem item, String position) {
        _statusItems.addElement(item);
        _statusItemPositions.addElement(position);
    }


    /**
     * removes status item to a list of status items managed by this page
     * Called by ResourceModel
     * Implements IResourceModelListener
     */
    private void removeStatusItem(IStatusItem item) {
        int index = _statusItems.indexOf(item);
        _statusItems.removeElementAt(index);
        _statusItemPositions.removeElementAt(index);
    }


    /**
     */
    protected void populateStatusItems() {
        if (isPageSelected()) {
            for (int i = 0; i < _statusItems.size(); i++) {
                IStatusItem item = (IStatusItem)_statusItems.elementAt(i);
                String position = (String)_statusItemPositions.elementAt(i);
                _framework.addStatusItem(item, position);
            }
        }
    }

    /**
     */
    protected void unpopulateStatusItems() {
        if (isPageSelected()) {
            for (int i = _statusItems.size() - 1; i >= 0; i--) {
                IStatusItem item = (IStatusItem)_statusItems.elementAt(i);
                _framework.removeStatusItem(item);
            }
        }
    }

    /**
     * Use when status items need to be added.
     * Called by ResourceModel
     * Implements IResourceModelListener
     */
    public void addStatusItem(ResourceModelEvent e) {
        if (isEventTarget(e)) {
            IStatusItem item = e.getStatusItem();
            String position = e.getStatusItemPosition();
            addStatusItem(item, position); // add to local list of managed status items
            _framework.addStatusItem(item, position);
        }
    }

    /**
     * Use when status items need to be removed.
     * Called by ResourceModel
     * Implements IResourceModelListener
     */
    public void removeStatusItem(ResourceModelEvent e) {
        if (isEventTarget(e)) {
            removeStatusItem(e.getStatusItem()); // remove from local list of managed status items
            _framework.removeStatusItem(e.getStatusItem());
        }
    }

    /**
     * Use when status item state has changed.
     * Called by ResourceModel
     * Implements IResourceModelListener
     */
    public void changeStatusItemState(ResourceModelEvent e) {
        if (isEventTarget(e)) {
            if (isPageSelected())
                _framework.changeStatusItemState(e.getStatusItemID(),
                        e.getStatusItemState());
        }
    }

    /**
     * Use to change right hand side detail panel.
     * Called by: ResourceModel
     */
    public void changeCustomPanel(ResourceModelEvent e) {
        if (isEventTarget(e)) {
            setCustomPanel(e.getCustomPanel());
        }
    }

    /**
     * Use to change mouse cursor shape.
     * Called by: ResourceModel
     */
    public void changeFeedbackCursor(ResourceModelEvent e) {
        if (isEventTarget(e)) {
        	if (e.getCursor().getType() == Cursor.WAIT_CURSOR &&
        	    _framework instanceof Framework) {
        	    	
        		((Framework)_framework).setBusyCursor(true);
        	}
        	else if (e.getCursor().getType() == Cursor.DEFAULT_CURSOR &&
        	         _framework instanceof Framework) {
        	         	
        		((Framework)_framework).setBusyCursor(false);
        	}
        	else {
            	_framework.setCursor(e.getCursor());
            }
        }
    }

    /**
     * returns true if page is currently selected
     */
    public boolean isPageSelected() {
        return _isPageSelected;
    }

    /**
     * Called by Framework when page is selected
     */
    public void pageSelected(IFramework framework) {
        _isPageSelected = true;
        populateMenuItems(_menuData);
        populateStatusItems();

        // Select the first object if nothing selected in the tree
        if (_tree.getComponentCount() > 0 && getSelection() == null) {
            // Select the first object.
            _tree.setSelectionRow(0);
        }

    }

    /**
     * Called by Framework when page is unselected
     */
    public void pageUnselected(IFramework framework) {
        unpopulateMenuItems(_menuData);
        unpopulateStatusItems();
        _isPageSelected = false;
    }

    /**
     * Notification that the framework window is closing.
     */
    public void actionViewClosing(IFramework parent)
            throws CloseVetoException {
        getModel().actionViewClosing(this);
    }

    class MenuInfoAction implements ActionListener {
        public void actionPerformed(ActionEvent event) {
            IMenuItem menuItem = (IMenuItem) event.getSource();
            IMenuInfo menuInfo = MenuData.findIMenuInfo(
                    ResourcePage.this._menuData, menuItem);
            menuInfo.actionMenuSelected(ResourcePage.this, menuItem);
        }
    }

    class TreeToggleAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            JCheckBoxMenuItem button = (JCheckBoxMenuItem) e.getSource();
            setMainPanel(button.getState());
            ResourcePage.this.validate();
            ResourcePage.this.repaint();
        }
    }

    private void setMainPanel(boolean b) {
        _isTreeVisible = b;
        if (_isTreeVisible) {
            ResourcePage.this.remove(_customPanel);
            _splitPanel.setRightComponent(_customPanel);
            ResourcePage.this.add(_splitPanel);
        } else {
            ResourcePage.this.remove(_splitPanel);
            ResourcePage.this.add(_customPanel);
        }
        PreferenceManager pm = PreferenceManager.getPreferenceManager(
                Framework.IDENTIFIER, Framework.MAJOR_VERSION);
        Preferences p = pm.getPreferences(PREFERENCES_RESOURCES);
        p.set(PREFERENCE_SHOW_TREE, _isTreeVisible);
    }

    public void keyTyped(KeyEvent e) {
    }

    public void keyPressed(KeyEvent e) {
        if (e.getKeyCode() == KeyEvent.VK_ENTER) {
            IResourceObject[] selection = getSelection();
            if (selection != null) {
                if (selection.length == 1)// single selection
                {
                    if (!_model.isLeaf(selection[0]))
                        return;
                }
                _model.actionObjectRun(this, selection);
            }
        }
    }

    public void keyReleased(KeyEvent e) {
    }

    /**
     * Expand tree path view
     */
    public void expandTreePath(TreePath path) {
        _tree.expandPath(path);
    }

    /**
     * Expand tree row
     */
    public void expandTreeRow(int i) {
        _tree.expandRow(i);
    }

    /**
     * Select tree row
     */
    public void selectTreeRow(int i) {
        _tree.setSelectionRow(i);
    }

    /**
     * Use to select a tree node.
     * Called by: ResourceModel
     */
    public void selectTreeNode(ResourceModelEvent e) {
        if (isEventTarget(e)) {
            _tree.setSelectionPath(e.getTreePath());
        }
    }

    /**
     * Use to expand a tree node.
     * Called by: ResourceModel
     */
    public void expandTreeNode(ResourceModelEvent e) {
        if (isEventTarget(e)) {
            _tree.expandPath(e.getTreePath());
        }
    }
}
