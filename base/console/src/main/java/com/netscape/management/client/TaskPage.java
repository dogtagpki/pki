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
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.border.*;
import com.netscape.management.client.console.*;
import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;

/**
 * This page view (appears as a tab in Console) displayes a task list.
 * Tasks are organized in a flat list, with a pushbutton on the
 * left and text on the right.  The user an access the task by
 * single-clicking the pushbutton, or by a menu item.
 *
 * The task list data is supplied by an ITaskModel interface.
 *
 * @see IPage
 * @see TaskModel
 * @see ITaskModelListener
 */
public class TaskPage extends JPanel implements IPage,
ITaskModelListener, Cloneable, SuiConstants {
    public static final String MENU_CONTEXT = "CONTEXT";
    public static final String STATUS_PROGRESS = "StatusItemProgress";

    // TODO: document these variables + set access modifiers correctly.
    protected IFramework _framework;
    protected ITaskModel _model;
    protected TaskList _taskList;
    protected String _pageTitle = "";
    protected JPopupMenu _contextMenu = new JPopupMenu();
    protected ITaskObject _selectedTask;
    protected ITaskObject _previousSelectedTask;
    protected MenuInfoAction _menuInfoAction = new MenuInfoAction();
    protected Vector _menuData = new Vector(); // MenuData objects
    protected Vector _statusItems = new Vector(); // IStatusItem objects
    protected Vector _statusItemPositions = new Vector();
    protected boolean _isPageSelected = false;
    public static Icon _defaultTaskIcon;
    protected ConsoleInfo _info; // TODO: get rid of this
    protected StatusItemProgress _statusItemProgress =
            new StatusItemProgress(STATUS_PROGRESS, 0);

    /**
     * Return TaskPage and set the data model specified.
     */
    public TaskPage(ITaskModel taskModel) {
        if (_defaultTaskIcon == null) {
            _defaultTaskIcon =
                    new RemoteImage(Framework._imageSource + "task.gif");
        }
        setTaskModel(taskModel);
    }

    /**
     * Return TaskPage and set the data model specified.
     */
    public TaskPage(ConsoleInfo info, ITaskModel taskModel) {
        this(taskModel);
        _info = info;
    }

    /**
     * Return TaskPage that uses LDAPTaskModel.  This contructor
     * creates a data model that reads task information from an
     * LDAP server.  Server name and credentials are supplied in ConsoleInfo.
     */
    public TaskPage(ConsoleInfo info) {
        this(info, LDAPTaskModel.createTaskModel(info));
    }

    /**
     *	Returns the framework in which this page is this displayed.
     *	Implementation: return parent parameter in initialize(...)
     */
    public IFramework getFramework() {
        return _framework;
    }

    /**
     *	Return exact copy of this page, maintaining state info.
     *  Called by IFramework when user selects File->New Window.
     *  TODO: if you subclass, you need to override
     *        this method and clone your own class. BUG!
     */
    public Object clone() {
        TaskPage page = new TaskPage(_info, _model);
        page.setPageTitle(getPageTitle());
        return page;

        // TODO: figure out why the following code doesn't work
        /*		try
        		{
        			return (IPage)this.clone();
        		}
        		catch(CloneNotSupportedException e)
        		{
        			Debug.println("TaskPage.clone: Could not clone");
        		}
        		return (IPage)null; */
    }

    /**
     *	Sets data model for this page.
     */
    public void setTaskModel(ITaskModel taskModel) {
        _model = taskModel;
        _pageTitle = Framework.i18n("page", "Tasks");
        setLayout(new BorderLayout());
		removeAll();
        add(createTaskPanel(getModel()));
		validate();
    }

    /**
     *	Returns a JPanel that contains the visuals for this page
     */
    protected Component createTaskPanel(ITaskModel taskModel) {
        _taskList = new TaskList(taskModel);
        JScrollPane treePanel = new JScrollPane();
        treePanel.getViewport().add(_taskList);
        Border b1 = new BevelBorder(BevelBorder.LOWERED,
                UIManager.getColor("controlHighlight"),
                UIManager.getColor("control"),
                UIManager.getColor("controlDkShadow"),
                UIManager.getColor("controlShadow"));
        Border b2 = new EmptyBorder(COMPONENT_SPACE, COMPONENT_SPACE,
                COMPONENT_SPACE, COMPONENT_SPACE);
        treePanel.setBorder(new CompoundBorder(b2, b1));
        return treePanel;
    }

    /**
     *	Return data model
     */
    public ITaskModel getModel() {
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
     *	Initializes page.  Called after construction or after clonePage().
     *  The reference to IFramework allows this page to set menu items, status
     *  bars, and add event notification listeners.
     */
    public void initialize(IFramework parent) {
        _framework = parent;

        if (_model instanceof IMenuInfo)
            addMenuItems((IMenuInfo)_model, _menuInfoAction);

        _model.addITaskModelListener(this);
        addStatusItem(_statusItemProgress, IStatusItem.RIGHT);
    }

    /**
     * Return the selected ITaskObject
     */
    public ITaskObject getSelection() {
	Debug.println(6, "TaskPage.getSelection: sel=" + _selectedTask);
        return _selectedTask;
    }

    /**
     * Return the selected ITaskObject
     */
    public ITaskObject getPreviousSelection() {
	Debug.println(6, "TaskPage.getPreviousSelection: sel=" + _previousSelectedTask);
        return _previousSelectedTask;
    }

    /**
     * Called after run is complete (for each listener).  ranObject specifies
     * which object elected to run.  If no object ran, the value is null.
     * Override this method to display error/success dialogs, etc.
     */
    public void runComplete(ITaskObject ranObject) {
    }

    /**
     * Checks to see if the event is intended for this page.
     */
    private boolean isEventTarget(TaskModelEvent e) {
        IPage targetPage = e.getViewInstance();
        if (targetPage == null)
            return true;

        if (targetPage == this)
            return true;

        return false;
    }

    /**
     * Use when menu items have been added.
     * Called by TaskModel
     * Implements ITaskModelListener
       */
    public void addMenuItems(TaskModelEvent e) {
        if (isEventTarget(e)) {
            addMenuItems(e.getMenuInfo(), _menuInfoAction);
        }
    }

    /**
     * Use when menu items have been added.
     * Called by TaskModel
     * Implements ITaskModelListener
     */
    public void enableMenuItem(TaskModelEvent e) {
        if (isEventTarget(e)) {
            MenuData.enableMenuItem(_menuData, e.getMenuID(), true);
        }
    }

    /**
     * Use when menu items have been added.
     * Called by TaskModel
     * Implements ITaskModelListener
     */
    public void disableMenuItem(TaskModelEvent e) {
        if (isEventTarget(e)) {
            MenuData.enableMenuItem(_menuData, e.getMenuID(), false);
        }
    }

    /**
     * Use when menu items have been added.
     * Called by TaskModel
     * Implements ITaskModelListener
     */
    protected void addMenuItem(String categoryID, IMenuItem menuItem) {
        MenuData menuData =
                new MenuData(categoryID, menuItem, (IMenuInfo) null);
        populateMenuItem(menuData);
        _menuData.addElement(menuData);
    }

    /**
     */
    private void populateMenuItem(MenuData menuData) {
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

    private void populateMenuItems(Vector menuDataVector) {
        Enumeration e = menuDataVector.elements();
        while (e.hasMoreElements()) {
            populateMenuItem((MenuData) e.nextElement());
        }
    }

    private void unpopulateMenuItems(Vector menuDataVector) {
        if (isPageSelected()) {
            Enumeration e = menuDataVector.elements();
            while (e.hasMoreElements()) {
                MenuData menuData = (MenuData) e.nextElement();
                if (menuData.getCategoryID().equals(MENU_CONTEXT)) {
                    _contextMenu.remove(
                            menuData.getIMenuItem().getComponent());
                } else {
                    JMenu menu = MenuData.getMenu(_contextMenu,
                            menuData.getCategoryID());
                    if (menu != null) {
                        menu.remove(
                                menuData.getIMenuItem().getComponent());
                    } else {
                        _framework.removeMenuItem(menuData.getIMenuItem());
                    }
                }
            }
        }
    }

    /**
     * Use when menu items have been added.
     * Called by TaskModel
     * Implements ITaskModelListener
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
     * Called by TaskModel
     * Implements ITaskModelListener
     */
    public void removeMenuItems(TaskModelEvent e) {
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
     * Implements ITaskModelListener
     */
    private void addStatusItem(IStatusItem item, String position) {
        _statusItems.addElement(item);
        _statusItemPositions.addElement(position);
    }


    /**
     * removes status item to a list of status items managed by this page
     * Called by TaskModel
     * Implements ITaskModelListener
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
     * Called by TaskModel
     * Implements ITaskModelListener
     */
    public void addStatusItem(TaskModelEvent e) {
        if (isEventTarget(e)) {
            IStatusItem item = e.getStatusItem();
            String position = e.getStatusItemPosition();
            addStatusItem(item, position); // add to local list of managed status items
            _framework.addStatusItem(item, position);
        }
    }

    /**
     * Use when status items need to be removed.
     * Called by TaskModel
     * Implements ITaskModelListener
     */
    public void removeStatusItem(TaskModelEvent e) {
        if (isEventTarget(e)) {
            removeStatusItem(e.getStatusItem()); // remove from local list of managed status items
            _framework.removeStatusItem(e.getStatusItem());
        }
    }

    /**
     * Use when status item state has changed.
     * Called by TaskModel
     * Implements ITaskModelListener
     */
    public void changeStatusItemState(TaskModelEvent e) {
        if (isEventTarget(e)) {
            if (isPageSelected())
                _framework.changeStatusItemState(e.getStatusItemID(),
                        e.getStatusItemState());
        }
    }

    /**
     * Use to change mouse cursor shape.
     * Called by: TaskModel
     */
    public void changeFeedbackCursor(TaskModelEvent e) {
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
     * Returns true if page is currently selected
     */
    public boolean isPageSelected() {
        return _isPageSelected;
    }

    /**
     * Called by Framework when page is selected
     */
    public void pageSelected(IFramework parent) {
	Debug.println(6, "TaskPage.pageSelected: parent=" + parent);
        _isPageSelected = true;
        populateMenuItems(_menuData);
        populateStatusItems();
    }


    /**
     * Called by Framework when page is unselected
     */
    public void pageUnselected(IFramework parent) {
	Debug.println(6, "TaskPage.pageUnselected: parent=" + parent);
        unpopulateMenuItems(_menuData);
        unpopulateStatusItems();
        _isPageSelected = false;
    }


    /**
     * Notification that the framework window is closing.
     *
     * @exception CloseVetoException If the page does not want to close (may be missing information),
     *  it will throws a CloseVetoException.
     */
    public void actionViewClosing(IFramework parent)
            throws CloseVetoException {
        getModel().actionViewClosing(this);
    }

    class MenuInfoAction implements ActionListener {
        public void actionPerformed(ActionEvent event) {
            IMenuItem menuItem = (IMenuItem) event.getSource();
            IMenuInfo menuInfo =
                    MenuData.findIMenuInfo(TaskPage.this._menuData,
                    menuItem);
            menuInfo.actionMenuSelected(TaskPage.this, menuItem);
        }
    }

    class TaskList extends JPanel implements SwingConstants,
					     SuiConstants { // , Scrollable {
        LabelMouseListener _labelListener = new LabelMouseListener();
        ButtonMouseListener _buttonListener = new ButtonMouseListener();
	TaskKeyListener _keyListener = new TaskKeyListener();
	TaskFocusListener _focusListener = new TaskFocusListener();
        ITaskModel _taskModel;
        int SPACE = COMPONENT_SPACE;
        VisibleTask _visibleTask = null;
        JSeparator _separator = null;

        public TaskList(ITaskModel taskModel) {
            _taskModel = taskModel;
            this.setLayout(new GridBagLayout());
            this.setBackground(UIManager.getColor("window"));
            Object root = _taskModel.getRoot();
            int childCount = _taskModel.getChildCount(root);
            for (int i = 0; i < childCount; i++) {
                ITaskObject taskObject =
                        (ITaskObject)_taskModel.getChild(root, i);
                _visibleTask = new VisibleTask(taskObject);
                _visibleTask.addMouseListener(_labelListener);
		// _visibleTask.addFocusListener(_focusListener);
                GridBagUtil.constrain(this, _visibleTask, 0,
                        GridBagConstraints.RELATIVE, 1, 1, 1.0, 0.0,
                        GridBagConstraints.WEST,
                        GridBagConstraints.HORIZONTAL, SPACE, SPACE,
                        SPACE, SPACE);
                if (i != childCount - 1) {
                    _separator = new JSeparator();
                    GridBagUtil.constrain(this, _separator, 0,
                            GridBagConstraints.RELATIVE, 1, 1, 1.0,
                            0.0, GridBagConstraints.WEST,
                            GridBagConstraints.HORIZONTAL, 0, 0, 0, 0);
                }
            }
            JPanel spacerPanel = new JPanel();
            spacerPanel.setOpaque(false);
            GridBagUtil.constrain(this, spacerPanel, 0,
                    GridBagConstraints.RELATIVE, 1, 1, 1.0, 1.0,
                    GridBagConstraints.WEST, GridBagConstraints.BOTH,
                    0, 0, 0, 0);

        }

//          /**
//           * implements Scrollable
//           */
//          public Dimension getPreferredScrollableViewportSize() {
//              return this.getPreferredSize();
//          }

//          /**
//           * implements Scrollable
//           */
//          public int getScrollableBlockIncrement(
//                  java.awt.Rectangle visibleRect, int orientation,
//                  int direction) {
//              return (orientation == SwingConstants.VERTICAL) ?
//                      visibleRect.height : visibleRect.width;
//          }

//          /**
//           * implemens Scrollable
//           */
//          public boolean getScrollableTracksViewportHeight() {
//              return true;
//          }


//          /**
//           * implements Scrollable
//           */
//          public boolean getScrollableTracksViewportWidth() {
//              return true;
//          }

//          /**
//           * implements Scrollable
//           */
//          public int getScrollableUnitIncrement(
//                  java.awt.Rectangle visibleRect, int orientation,
//                  int direction) {
//              if (orientation == SwingConstants.VERTICAL)
//                  return SPACE + _visibleTask.getHeight() + SPACE + 3; // top margin + height + bot margin + separator
//              else
//                  return 16; // width
//          }

        class VisibleTask extends JPanel {
            ITaskObject _taskObject;
            JButton button;

            public VisibleTask(ITaskObject taskObject) {
                _taskObject = taskObject;
                this.setLayout(new GridBagLayout());
                this.setOpaque(false);
                Icon taskIcon = taskObject.getIcon();
                button = new JButton(taskIcon == null ?
                        _defaultTaskIcon : taskIcon);
                button.setToolTipText(taskObject.getDescription());
                button.setFocusPainted(true);
                // button.setOpaque(true);
                button.setMargin(new Insets(0, 0, 0, 0));
                button.addMouseListener(_buttonListener);
		button.addKeyListener(_keyListener);
		button.addFocusListener(_focusListener);
                GridBagUtil.constrain(this, button, 0, 0, 1, 1, 0.0,
                        0.0, GridBagConstraints.WEST,
                        GridBagConstraints.NONE, 0, 0, 0, 0);

                JLabel label = new JLabel(taskObject.getName());
                label.setOpaque(false);
                label.setHorizontalTextPosition(LEFT);
                label.setFont(UIManager.getFont("TaskList.font"));
                label.setBorder( BorderFactory.createEmptyBorder(0,
                        COMPONENT_SPACE, 0, 0));
                GridBagUtil.constrain(this, label, 1, 0, 1, 1, 1.0,
                        0.0, GridBagConstraints.WEST,
                        GridBagConstraints.HORIZONTAL, 0, 3, 0, 0);
            }

            public void selected() {
                this.getRootPane().setDefaultButton(button);
            }

	    public void requestFocus() {
		button.requestFocus();
	    }

            public ITaskObject getTaskObject() {
                return _taskObject;
            }
        }

	class TaskFocusListener extends FocusAdapter {
	    public void focusGained(FocusEvent e) {
		Debug.println(7, "Focus gained " + e.getSource());
                VisibleTask visibleTask = (VisibleTask) e.getComponent().getParent();
                visibleTask.selected();
                _previousSelectedTask = _selectedTask;
                _selectedTask = visibleTask.getTaskObject();
                _taskModel.actionObjectSelected(TaskPage.this,
						_selectedTask, _previousSelectedTask);

	    }
	    public void focusLost(FocusEvent e) {
		Debug.println(7, "Focus lost " + e.getSource());
	    }
	}
	
        class LabelMouseListener extends MouseAdapter {
            public void mouseClicked(MouseEvent e) {
            }

            public void mousePressed(MouseEvent e) {
		Debug.println(7, "TaskPage.LabelMouseListener.mousePressed " + e.getSource());
                VisibleTask visibleTask = (VisibleTask) e.getSource();
		visibleTask.requestFocus();
                // visibleTask.selected();
                // _previousSelectedTask = _selectedTask;
                // _selectedTask = visibleTask.getTaskObject();
                // _taskModel.actionObjectSelected(TaskPage.this,
                //         _selectedTask, _previousSelectedTask);
                if ((_contextMenu != null) && (e.isPopupTrigger())) {
                    if (_contextMenu.getComponentCount() > 0)
                        _contextMenu.show((Component) e.getSource(),
                                e.getX(), e.getY());
                }
            }

            public void mouseReleased(MouseEvent e) {
		Debug.println(7, "TaskPage.LabelMouseListener.mouseReleased " + e.getSource());
                if ((_contextMenu != null) && (e.isPopupTrigger())) {
                    if (_contextMenu.getComponentCount() > 0)
                        _contextMenu.show((Component) e.getSource(),
                                e.getX(), e.getY());
                }
            }
        }

        class ButtonMouseListener extends MouseAdapter {
            public void mouseClicked(MouseEvent e) {
		Debug.println(7, "TaskPage.ButtonMouseListener.mouseClicked");
                if (e.getClickCount() == 1) {
                    JButton button = (JButton) e.getSource();
                    VisibleTask visibleTask =
                            (VisibleTask) button.getParent();
                    visibleTask.selected();
		    
		    // isClosing() required to discard extra event
		    // received as a result of Menu | Close.
		    // This is a JFC/AWT/Solaris bug 4119268.
		    // TODO: when above bug is fixed, remove this hack.
		    if(!((Framework)getFramework()).isClosing())
		    {
			_taskModel.actionObjectRun(TaskPage.this,
			        visibleTask.getTaskObject());
		    }
                }
            }
        }

        class TaskKeyListener implements KeyListener {
            public void keyTyped(KeyEvent e) {
            }

            public void keyPressed(KeyEvent e) {
		Debug.println(7, "TaskPage.TaskKeyListener.keyPressed " + e.getSource());		
                if (e.getKeyCode() == KeyEvent.VK_ENTER || e.getKeyCode() == KeyEvent.VK_SPACE) {
		    Object o = e.getSource();
		    if (o instanceof AbstractButton) {
			((AbstractButton)o).doClick();
		    }
		    ITaskObject selection = (ITaskObject) getSelection();
		    if (selection != null) {
                        _taskModel.actionObjectRun(TaskPage.this,
						   selection);
                    }
                }
            }

            public void keyReleased(KeyEvent e) {
            }
        }
    }
}
