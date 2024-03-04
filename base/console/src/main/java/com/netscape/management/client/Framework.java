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
import java.beans.*;
import java.net.URL;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.event.*;
import com.netscape.management.client.util.*;
import com.netscape.management.client.console.*;
import com.netscape.management.client.preferences.*;
import com.netscape.management.client.components.*;
import com.netscape.management.nmclf.*;

/**
 * An implementation of IFramework that creates the Console window.
 * The Console window provides common functionality such as a menu bar,
 * one or more tabbed panes, and a status bar.  The details of these
 * properties are specified through various interfaces in this
 * package.  The starting point is the IFrameworkInitalizer interface.
 *
 * @see IFrameworkInitializer
 */
public class Framework extends JFrame implements IFramework, SuiConstants {
    public static final String IDENTIFIER = Console.IDENTIFIER;
    public static final String VERSION = Console.VERSION;
    public static final String MAJOR_VERSION = Console.MAJOR_VERSION;

    public static final String PREFERENCES_GENERAL = "General";
    public static final String PREFERENCES_FONTS = "Fonts";

    public static final String PREFERENCE_X = "X";
    public static final String PREFERENCE_Y = "Y";
    public static final String PREFERENCE_WIDTH = "Width";
    public static final String PREFERENCE_HEIGHT = "Height";
    public static final String PREFERENCE_SHOW_BANNER = "ShowBannerBar";
    public static final String PREFERENCE_SHOW_STATUS = "ShowStatusBar";
    public static final String PREFERENCE_AUTO_SAVE = "AutoSave";

    public static final String MENU_TOP = "<top>";
    public static final String MENU_FILE = "FILE";
    public static final String MENU_EDIT = "EDIT";
    public static final String MENU_VIEW = "VIEW";
    public static final String MENU_HELP = "HELP";
    public static final String MENU_HELPWEBHELP = "HELPWEBHELP";
    public static final String MENU_HELPCONTENTS = "HELPCONTENTS";
    public static final String MENU_HELPINDEX = "HELPINDEX";
    public static final String MENU_HELPDOCHOME = "HELPDOCHOME";

    public static final String STATUS_TEXT = "StatusItemText";
    public static final String STATUS_SECURE_MODE = "StatusItemSecureMode";

    public static final int DEFAULT_WIDTH = 750;
    public static final int DEFAULT_HEIGHT = 530;

    private static Point _initialLocation = null;
    private static Dimension _initialDimension = null;
    private Image _bannerImage = null;

    public static String _imageSource = "com/netscape/management/client/images/";
    public static ResourceSet _resource = new ResourceSet("com.netscape.management.client.default");
    public static ResourceSet _resource_theme = new 
            ResourceSet("com.netscape.management.client.theme.theme");
    public static Help _help = new Help("com.netscape.management.client.default");

    protected boolean _isPageInitialized[];
    protected IFrameworkInitializer _frameworkInitializer;
    protected JPanel _framePanel;
    protected JPanel _pagePanel;
    protected JPanel _customPanel;
    protected JPanel _bannerPanel;
    protected JPanel _statusPanel;
    protected JTabbedPane _tabbedPane;
    protected JMenuBar _menuBar;
    protected Box _statusBarLeft;
    protected Box _statusBarCenter;
    protected Box _statusBarRight;
    protected Vector _statusBarList = new Vector();
    protected IPage _pageList[];

    protected boolean _isBannerBarVisible = true;
    protected boolean _isStatusBarVisible = true;
    protected ButtonGroup _tabButtonGroup = new ButtonGroup();
    protected StatusItemText _statusItemText;
    protected static Color _bannerBackground;
    protected MenuItemCheckBox _bannerMenuItem;

    protected static boolean _enableWinPositioning = true;

    private boolean _busyCursorOn;

    private boolean _isTopologyFramework = false;
    private boolean _isClosing = false;
    private static PreferenceManager _preferenceManager;
    private UIPermissions _uiPermissions = null;
    private String _helpdir = "admin";

    private WindowAdapter _windowAdaptor = new WindowAdapter() {
                public void windowActivated(WindowEvent e) {
                    UtilConsoleGlobals.setActivatedFrame(
                            (JFrame) e.getSource());
                }
                public void windowOpened(WindowEvent e) {
                    UtilConsoleGlobals.setActivatedFrame(
                            (JFrame) e.getSource());
                }

            };


    
    
    /**
    * Constructs Framework object without anything in it.
    */
    public Framework() {
        UtilConsoleGlobals.incrementWindowCount(); // Increment open Framework window count by 1.

        Debug.println(Debug.TYPE_GC,
                Debug.KW_CREATE + "Framework " + getName());

        //root frame
        if (UtilConsoleGlobals.getWindowCount() == 1) {
            UtilConsoleGlobals.setRootFrame(this);
        }
		setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE); // bug 341277
    }

    /**
     * Constructs a Framework object with the specified 
     * initializer object that serves as its "model".
     * 
     * @param initializer   an IFrameworkInitializer object
     */
    public Framework(IFrameworkInitializer initializer) {
        this();
        _frameworkInitializer = initializer;
        if(initializer instanceof FrameworkInitializer)
        {
            _uiPermissions = ((FrameworkInitializer)initializer).getUIPermissions();
        }
        loadPreferences();
        _isTopologyFramework =
                (initializer instanceof com.netscape.management.client.topology.TopologyInitializer);
        initializeUI();
        initializePages(initializer);
        show();
    }

    /**
     * Retrieves the UIPermissions object associated with
     * this Framework object.  This object is set by 
     * FrameworkInitializer.setUIPermissions();
     * 
     * @return UIPermissions object
     */
    public UIPermissions getUIPermissions()
    {
        return _uiPermissions;
    }
    
    protected void finalize() throws Throwable {
        Debug.println(Debug.TYPE_GC,
                Debug.KW_FINALIZE + "Framework " + getName());
        super.finalize();
    }

    /**
      * Return localized string from the framework resource bundle
      */
    public static String i18n(String group, String id) {
        return _resource.getString(group, id);
    }

    /**
     *      Creates framework UI.  Called internally after construction.
     */
    protected void initializeUI() {
        setBackground(UIManager.getColor("control"));
        _menuBar = createDefaultMenuBar();
        setJMenuBar(_menuBar);

        _framePanel = new JPanel();
        _framePanel.setLayout(new BorderLayout());
        _framePanel.setBorder(
                BorderFactory.createEmptyBorder(2, HORIZ_WINDOW_INSET,
                2, HORIZ_WINDOW_INSET));

        _bannerPanel = new JPanel(new BorderLayout());
        _bannerPanel.getAccessibleContext().setAccessibleDescription(
                _resource_theme.getString("banner","console") + " " +
                VersionInfo.getVersionNumber());
        _bannerPanel.setBorder(
                BorderFactory.createEmptyBorder(0, 0, 0, 0));

        _pagePanel = new JPanel();
        _pagePanel.setLayout(new BorderLayout());
        _pagePanel.setBorder(BorderFactory.createEmptyBorder(0, 0, 2, 0));
        _tabbedPane = new JTabbedPane();
        _pagePanel.add(_tabbedPane);
        _framePanel.add("Center", _pagePanel);

        _statusBarLeft = Box.createHorizontalBox();
        _statusBarCenter = Box.createHorizontalBox();
        _statusBarRight = Box.createHorizontalBox();
        _statusBarLeft.add(Box.createVerticalStrut(15)); // this is a guestimate of text size, should be more dynamic
        _statusPanel = new JPanel();
        _statusPanel.setLayout(new BorderLayout());
        _statusPanel.add("West", _statusBarLeft);
        _statusPanel.add("Center", _statusBarCenter);
        _statusPanel.add("East", _statusBarRight);
        _statusItemText = new StatusItemText(STATUS_TEXT);
	_statusItemText.setFont(UIManager.getFont("Status.font"));
        this.addStatusItem(_statusItemText, IStatusItem.LEFTFIRST);

        TabChangeActionListener tabChangeActionListener =
                new TabChangeActionListener();

        addWindowListener(_windowAdaptor);
    }

    protected void initializePages(IFrameworkInitializer initializer) {
        setTitle(initializer.getFrameTitle());
        setIconImage(initializer.getMinimizedImage());
        _bannerImage = initializer.getBannerImage();
        if (_bannerImage != null) {
            _bannerPanel.add(BorderLayout.WEST,
                    new JLabel(new ImageIcon(_bannerImage)));
            _bannerBackground = new ImageInfo(
                    _bannerImage).getTopRightAverageColor(4);
            if (!_isTopologyFramework) {
                JLabel bannerText = new JLabel(initializer.getBannerText());
                bannerText.setForeground(Color.white); // TODO: don't hardcode this
                _bannerPanel.add(BorderLayout.CENTER, bannerText);
            }
        } else {
            _isBannerBarVisible = false;
            _bannerBackground = getBackground();
            _bannerMenuItem.setChecked(false);
            _bannerMenuItem.setEnabled(false);
        }

        int index;
        int pageCount = initializer.getPageCount();
        _pageList = new IPage[pageCount];
        for (index = 0; index < pageCount; index++) {
            IPage page = initializer.getPageAt(index);
            _tabbedPane.addTab(page.getPageTitle(), null, (Component) page);
            _pageList[index] = page;
        }
        _isPageInitialized = new boolean[index];
        initializePages();
    }

    protected void initializeColors(Color background) {
        _bannerPanel.setBackground(background);
        _framePanel.setBackground(background);
        _pagePanel.setBackground(background);
        _statusPanel.setBackground(background);
        _statusBarLeft.setBackground(background);
        _statusBarCenter.setBackground(background);
        _statusBarRight.setBackground(background);
        if (_bannerBackground.equals(background))
            _statusItemText.setForeground(Color.white); // TODO: don't hardcode this
        else
            _statusItemText.setForeground(Color.black); // TODO: don't hardcode this
    }

    protected void initializePages() {
        setStatusPanel(_isStatusBarVisible);
        setBannerPanel(_isBannerBarVisible);
        getContentPane().add("Center", _framePanel);

        addWindowListener(new FrameworkWindowListener());

        TabChangeListener changeListener = new TabChangeListener();
        _tabbedPane.addChangeListener(changeListener);
        _tabbedPane.setSelectedIndex(0);
        changeListener.stateChanged((ChangeEvent) null); // initial page selection notification
    }


    public Color getBannerBackground() {
        if (_bannerBackground == null) {
            _bannerBackground = getBackground();
        }
        return _bannerBackground;
    }

    protected void setLocationOnScreen() {
        JFrame activeFrame = UtilConsoleGlobals.getActivatedFrame();
        if (activeFrame == null || !activeFrame.isVisible()) {
            setLocation(
                    ModalDialogUtil.calcWindowLocation(_initialDimension));
        } else {
            Point p0 = activeFrame.getLocationOnScreen();
            JMenuBar menuBar = activeFrame.getJMenuBar();

            if (menuBar == null) {
                setLocation( ModalDialogUtil.calcWindowLocation(
                        _initialDimension));
                Debug.println("Framework.setLocationOnScreen: no menu bar");
                return;
            }

            Point p = menuBar.getLocationOnScreen();
            p.x += p.y - p0.y - (p.x - p0.x);
            if (p.x < 0)
                p = new Point(0, 0);
            setLocation(p);
            Debug.println("Framework: location set: " + p);
        }
    }


    public static void setEnableWinPositioning(boolean flag) {
        _enableWinPositioning = flag;
    }

    /**
     * Returns the component associated with this framework window.
     * Called by: usually by someone (ex: IResourceObject) that needs a parent for a JDialog.
     */
    public JFrame getJFrame() {
        return this;
    }

    /**
     * Changes the cursor state on the entire framework window.
     * Called by: IPage
     */
    public void setCursor(Cursor cursor) {
        if (_busyCursorOn && cursor.getType() != Cursor.WAIT_CURSOR) {
            Debug.println(9, "Framework.setCursor(): Discarding change of cursor");
            return;
        }
        super.setCursor(cursor);
    }

    /**
    * Force the cursor for the whole frame to be busy.
    * See how _busyCursorOn flag is used inside setCursor
    */
    public void setBusyCursor(boolean isBusy) {
        this._busyCursorOn = isBusy;
        Cursor cursor =  Cursor.getPredefinedCursor(isBusy ?
                Cursor.WAIT_CURSOR : Cursor.DEFAULT_CURSOR);
        super.setCursor(cursor);
        setCursorOnChildren(this, cursor);
    }

	void setCursorOnChildren(Container container, Cursor cursor) {
		Component[] comps = container.getComponents();
		for (int i=0; i < comps.length; i++) {
			if (comps[i] instanceof Container) {
				setCursorOnChildren((Container)comps[i], cursor);
			}
            // JSplitPane divider cursor is lost if explictly set
            // Do not change the cursor on the divider
			if (comps[i].getClass().getName().indexOf("PaneDivider") >0) {
			    return;
			}    
			comps[i].setCursor(cursor);
		}
	}	

    /**
     * Adds status bar item.
     * Called by: IPage
     */
    public void addStatusItem(IStatusItem item, String position) {
        if (position.equals(IStatusItem.LEFTFIRST)) {
            _statusBarLeft.add(item.getComponent(), 0);
        } else if (position.equals(IStatusItem.LEFT)) {
            _statusBarLeft.add(item.getComponent());
        } else if (position.equals(IStatusItem.CENTER)) {
            _statusBarCenter.add(item.getComponent());
        } else if (position.equals(IStatusItem.CENTERFIRST)) {
            _statusBarCenter.add(item.getComponent(), 0);
        } else if (position.equals(IStatusItem.RIGHT)) {
            _statusBarRight.add(item.getComponent());
        } else if (position.equals(IStatusItem.RIGHTFIRST)) {
            _statusBarRight.add(item.getComponent(), 0);
        }
        _framePanel.validate();
        _framePanel.repaint();
    }

    private void removeStatusItem(Box box, IStatusItem item) {
        Component[] c = box.getComponents();
        for (int i = 0; i < c.length; i++) {
            if (item.getComponent() == c[i])
                box.remove(c[i]);
        }
    }


    /**
     * Removes status bar item.
     * Called by: IPage
     */
    public void removeStatusItem(IStatusItem item) {
        removeStatusItem(_statusBarLeft, item);
        removeStatusItem(_statusBarCenter, item);
        removeStatusItem(_statusBarRight, item);
        _framePanel.validate();
        _framePanel.repaint();
    }

    /**
     * Changes status item state.
     */
    public void changeStatusItemState(IStatusItem item) {
        changeStatusItemState(item.getID(), item.getState());
    }

    private void changeStatusItemState(Box box, String itemID,
            Object state) {
        Component[] c = box.getComponents();
        for (int index = 0; index < c.length; index++) {
            if (c[index] instanceof IStatusItem) {
                IStatusItem item = (IStatusItem) c[index];
                if (item.getID().equals(itemID)) {
                    item.setState(state);
                }
            }
        }
    }

    /**
     * Changes status item state.
     * Called by: IPage
     */
    public void changeStatusItemState(String itemID, Object state) {
        changeStatusItemState(_statusBarLeft, itemID, state);
        changeStatusItemState(_statusBarCenter, itemID, state);
        changeStatusItemState(_statusBarRight, itemID, state);
        _framePanel.validate();
        _framePanel.repaint();
    }

    /**
     * Adds menu item.
     * Called by: IPage
     */
    public void addMenuItem(String categoryID, IMenuItem menuItem) {
        if (categoryID.equals(MENU_TOP)) {
            if (menuItem.getComponent() instanceof JMenu) {
                Vector v = new Vector();

                // all this because there is no insert in JMenuBar
                for (int index = 0; index < _menuBar.getMenuCount();
                        index++)
                    v.addElement(_menuBar.getMenu(index));

                for (int index = 0; index < _menuBar.getMenuCount();
                        index++)
                    _menuBar.remove(index);

                v.insertElementAt(menuItem.getComponent(), v.size() - 1);

                for (Enumeration e = v.elements(); e.hasMoreElements();) {
                    _menuBar.add((JMenu) e.nextElement());
                }

                JMenu jmenu = (JMenu) menuItem.getComponent();
                if (jmenu.getMenuComponentCount() > 0)
                    jmenu.setEnabled(true);
                else
                    jmenu.setEnabled(false);

                _menuBar.validate();
                _menuBar.repaint();
            }
        } else {
            JMenu jmenu = MenuData.getMenu(_menuBar, categoryID);
            if (jmenu != null) {
                if (categoryID.equals(MENU_FILE)) {
                    int index = jmenu.getMenuComponentCount();
                    // index - 2 to account for Close and Exit
                    ((MenuItemCategory) jmenu).insert(
                            menuItem.getComponent(), index - 2);
                } else {
                    jmenu.add(menuItem.getComponent());
                }
                if (jmenu.getMenuComponentCount() > 0)
                    jmenu.setEnabled(true);
            }
        }
    }

    /**
     * Removes menu item.
     * Called by: IPage
     */
    public boolean removeMenuItem(IMenuItem item) {
        boolean result = false;
        for (int index = 0; index < _menuBar.getMenuCount(); index++) {
            JMenu menu = _menuBar.getMenu(index);
            if ((menu instanceof IMenuItem) && (menu == item)) {
                _menuBar.remove(index);
                _menuBar.validate();
                _menuBar.repaint();
                result = true;
                break;
            } else if (menu instanceof JMenu) {
                if (MenuData.removeMenuItem(menu, item) == true) {
                    menu.setPopupMenuVisible(false);
                    if (menu.getMenuComponentCount() == 0)
                        menu.setEnabled(false);
                    result = true;
                    break;
                }
            }
        }
        return result;
    }

    /**
      * selected the specified page
      *
      * @param iIndex index of the page
      */
    public void setSelectedPage(int iIndex) {
        _tabbedPane.setSelectedIndex(iIndex);
    }

    /**
     * Returns the currently selected (active, currently displayed) page.
     * Called by: IPage
     */
    public IPage getSelectedPage() {
        return(IPage)_tabbedPane.getComponentAt(
                _tabbedPane.getSelectedIndex());
    }

    private JMenuBar createDefaultMenuBar() {
        JMenuBar menuBar;
        MenuItemCategory fileMenu;
        MenuItemCategory editMenu;
        MenuItemCategory viewMenu;
        MenuItemCategory helpMenu;
        MenuItemCategory fileNewMenu;
        MenuItemCategory helpWebMenu;

        menuBar = new JMenuBar();
        fileMenu = new MenuItemCategory(MENU_FILE, i18n("menu", "File"));

        // If java is started with -Dprofile option we add these two item
        // They are used only for testing, so text does not need externalization
        if (Debug.gcTraceEnabled()) {
            fileMenu.addSeparator();
            fileMenu.add( new MenuItemText("Memory Check", null,
                    new MemCheckAction()));
            fileMenu.add(new MenuItemText("Run GC", null, new GCAction()));
            fileMenu.addSeparator();
        }

		MenuItemText menuItemText = new MenuItemText(i18n("menu", "FileClose"), "TODO:description",
                new CloseAction());
		menuItemText.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_W, 
				ActionEvent.CTRL_MASK)); 
        fileMenu.add(menuItemText);
		
		menuItemText = new MenuItemText(i18n("menu", "FileExit"), "TODO:description",
                new ExitAction());
		menuItemText.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_Q, 
				ActionEvent.CTRL_MASK)); 
        fileMenu.add(menuItemText);

        editMenu = new MenuItemCategory(MENU_EDIT, i18n("menu", "Edit"));
        editMenu.add(
                new MenuItemText(i18n("menu", "EditPreferences"), "TODO:description",
                new PreferencesAction()));

        viewMenu = new MenuItemCategory(MENU_VIEW, i18n("menu", "View"));
        _bannerMenuItem =
                new MenuItemCheckBox(i18n("menu", "ViewToggleBanner"),
                "TODO:description", new BannerBarToggleAction(),
                _isBannerBarVisible);
        viewMenu.add(_bannerMenuItem);
        viewMenu.add( new MenuItemCheckBox(i18n("menu", "ViewToggleStatus"),
                "TODO:description", new StatusBarToggleAction(),
                _isStatusBarVisible));
        if (!_isTopologyFramework) {
            viewMenu.add(
                    new MenuItemText(i18n("menu", "ViewShowRootTopology"),
                    "TODO:description", new ShowTopologyButtonAction()));
        }

        helpMenu = new MenuItemCategory(MENU_HELP, i18n("menu", "Help"));
/*		menuItemText = new MenuItemText(MENU_HELPCONTENTS, i18n("menu", "HelpContents"), "TODO:description",
                new HelpContentsAction());
		menuItemText.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.getKeyText(KeyEvent.VK_F1))); 
        helpMenu.add(menuItemText);
        helpMenu.add(
                new MenuItemText(MENU_HELPINDEX, i18n("menu", "HelpIndex"), "TODO:description",
                new HelpIndexAction()));
        helpMenu.addSeparator(); */

        helpMenu.add(
                new MenuItemText(MENU_HELPDOCHOME, i18n("menu", "HelpSuiteSpot"), "TODO:description",
                new HelpDocHomeAction()));
		
        helpMenu.addSeparator();
        helpMenu.add(
                new MenuItemText(i18n("menu", "HelpAbout"), "TODO:description",
                new HelpAboutAction()));

        menuBar.add(fileMenu);
        menuBar.add(editMenu);
        menuBar.add(viewMenu);
        menuBar.add(helpMenu);
        return menuBar;
    }

    private void loadFontPreferences(PreferenceManager preferenceManager)
    {
        Preferences p = preferenceManager.getPreferences(PREFERENCES_FONTS);
        if (!p.isEmpty()) 
        {
            Enumeration e = FontFactory.getFontIDs();
            while(e.hasMoreElements())
            {
                String fontID = (String)e.nextElement();
                String fontInfo = (String)p.get(fontID);
                if(fontInfo != null)
                    FontFactory.setFont(fontID, FontFactory.toFont(fontInfo));
            }
            FontFactory.initializeLFFonts();
        }
    }
    
    private void loadPreferences() {
        if (_preferenceManager == null)
            _preferenceManager =
                    PreferenceManager.getPreferenceManager(IDENTIFIER,
                    MAJOR_VERSION);

        Dimension screenSize = getToolkit().getScreenSize();
        // Bug 1261524 - Console window could be hidden after login via consoles on multiple hosts
        // The location on one window system could be invalid on the other window
        // which has a different resolution.  Don't set the location to avoid it.
        int sizex = screenSize.width;
        int sizey = screenSize.height;
        Preferences p = _preferenceManager.getPreferences(PREFERENCES_GENERAL);
        int x = p.getInt(PREFERENCE_X, 0);
        int y = p.getInt(PREFERENCE_Y, 0);
        if (x < -sizex / 2 || x > sizex / 2) {
            Debug.println( "Windows Location: coordinate x " + x + " is less than " + -sizex / 2 + " or greater than " + sizex / 2 + ". Resetting to 0.");
            x = 0;
        }
        if (y < -sizey / 2 || y > sizey / 2) {
            Debug.println( "Windows Location: coordinate y " + y + " is less than " + -sizey / 2 + " or greater than " + sizey / 2 + ". Resetting to 0.");
            y = 0;
        }
        _initialLocation = new Point(x, y);

        int width = p.getInt(PREFERENCE_WIDTH, DEFAULT_WIDTH);
        int height = p.getInt(PREFERENCE_HEIGHT, DEFAULT_HEIGHT);
        _initialDimension = new Dimension(width, height);

        setSize(_initialDimension);
        if (_enableWinPositioning) {
            if (_initialLocation.x != 0 &&
                    UtilConsoleGlobals.getActivatedFrame() == null)
                setLocation(_initialLocation.x, _initialLocation.y);
            else
                setLocationOnScreen();
        }
        _isBannerBarVisible = p.getBoolean(PREFERENCE_SHOW_BANNER, true);
        _isStatusBarVisible = p.getBoolean(PREFERENCE_SHOW_STATUS, true);

        loadFontPreferences(_preferenceManager);
    }

    private void savePreferences() {
        Preferences p =
                _preferenceManager.getPreferences(PREFERENCES_GENERAL);

        // TODO: move this to window move method, else breaks for manual save
        Point point = getLocation();
        p.set(PREFERENCE_X, point.x);
        p.set(PREFERENCE_Y, point.y);

        // TODO: move this to window resize method, else breaks for manual save
        Dimension d = getSize();
        p.set(PREFERENCE_WIDTH, d.width);
        p.set(PREFERENCE_HEIGHT, d.height);

        if (p.getBoolean(PREFERENCE_AUTO_SAVE, true))
            PreferenceManager.saveAllPreferences();
    }

    class FrameworkWindowListener implements WindowListener {
        public void windowOpened(WindowEvent e) {
            if (Debug.timeTraceEnabled()) {
                Debug.println(Debug.TYPE_RSPTIME, "Framework window shown");
            }
        }
        public void windowClosing(WindowEvent e) {
            Framework.this.closeFramework();
        }
        public void windowClosed(WindowEvent e) {
        }
        public void windowIconified(WindowEvent e) {
        }
        public void windowDeiconified(WindowEvent e) {
        }
        public void windowActivated(WindowEvent e) {
        }
        public void windowDeactivated(WindowEvent e) {
        }
    }

    /**
     * Sets the help directory for this instance of Framework.
     * The directory name is one level below manual/en/
     * For example, "manual/en/admin" for Admin Server.
     * By default, the help directory is set to "admin".
     * For an example of how this is used, see helpMenuInvoked().
     * 
     * @param dir    a string representing the product ID
     * @see @helpMenuInvoked
     */
    public void setHelpDirectory(String dir)
    {
        _helpdir = dir;
    }
    
    /**
     * Returns the help directory for this instance of Framework.
     * 
     * @return a string representing the help directory
     */
    public String getHelpDirectory()
    {
        return _helpdir;
    }
    
    /**
     * Called when a Help sub-menu item is selected.
     * The menuID parameter identifies which sub-menu has been selected.
     * It may be MENU_HELPCONTENTS, MENU_HELPINDEX, or MENU_HELPDOCHOME.
     * The default behavior launches an appropriate help UI.
     * When constructing the help URL, the string returned from getHelpDirectory() is used.
     * For example, if the help directory is "slapd", it might correspond to this URL:
     * http://host:6000/manual/help/help?helpdir=slapd&token=framework-menubar-contents&mapfile=tokens.map
     * 
     * @param menuID a string constant: MENU_HELPCONTENTS, MENU_HELPINDEX, or MENU_HELPDOCHOME
     */
    protected void helpMenuInvoked(String menuID)
    {
        if(menuID.equals(MENU_HELPCONTENTS))
        {
            Help.showContextHelp(getHelpDirectory(), "framework-menubar-contents");
        }
        else
        if(menuID.equals(MENU_HELPINDEX))
        {
            URL u = Help.getHelpUrl(getHelpDirectory(), "framework",
                                             "menubar-index",
                                             "topicindex.htm");
            final IndexDialog dlg = new IndexDialog( this, u );
            dlg.addPropertyChangeListener( new PropertyChangeListener() {
                public void propertyChange(PropertyChangeEvent evt) {
                    if ( evt.getPropertyName().equals(
                        IndexDialog.PROPERTY_NAME_URL ) ) {
                        String url = (String)evt.getNewValue();
                        Debug.println( "Selected URL: " + url );
                        if ( (url != null) && (url.length() > 0) ) {
                            if( dlg.isBrowserSelected() ) {
                                new Browser().open( url, Browser.NEW_WINDOW );
                            } else {
                                new BrowseHtmlDialog(
                                    null, url, true ).showModal();
                            }
                        }
                    }
                }
            } );
            dlg.show();
        }
        else
        if(menuID.equals(MENU_HELPDOCHOME))
        {
            // Launch a browser
            Browser browser = new Browser();
            boolean res = browser.open(_resource_theme.getString("menu", "HelpDocHome"),
                                       Browser.NEW_WINDOW);
        }
        else
            Debug.println("Unrecognized Help Menu ID: " + menuID);
    }
    
    class HelpContentsAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            helpMenuInvoked(MENU_HELPCONTENTS);
        }
    }

    class HelpIndexAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            helpMenuInvoked(MENU_HELPINDEX);
        }
    }

    class HelpDocHomeAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            helpMenuInvoked(MENU_HELPDOCHOME);
        }
    }

    class HelpAboutAction implements ActionListener {
        public HelpAboutAction() {
        }

        public void actionPerformed(ActionEvent e) {
            _frameworkInitializer.aboutInvoked(
                    UtilConsoleGlobals.getActivatedFrame());
        }
    }

    class CloseAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            Framework.this.closeFramework();
        }
    }

    class ExitAction implements ActionListener {
        public void actionPerformed(ActionEvent event) {
            Framework.this.exitFramework();
        }
    }

    class GCAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            long freemem0 = Runtime.getRuntime().freeMemory();
            long totlmem0 = Runtime.getRuntime().totalMemory();
            System.gc();
            long freemem1 = Runtime.getRuntime().freeMemory();
            long totlmem1 = Runtime.getRuntime().totalMemory();

            long delta = freemem1 - freemem0;
            String text = "  totlMem="+totlmem1 / 1024 + " freeMem="+
                    freemem1 / 1024 + " GCfreed="+ delta / 1024;

            changeStatusItemState(STATUS_TEXT, text);
            Debug.println(Debug.TYPE_GC, "Run GC, Heap:" + text);
        }
    }


    class MemCheckAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            long freemem = Runtime.getRuntime().freeMemory();
            long totlmem = Runtime.getRuntime().totalMemory();

            String text = "  totlMem="+totlmem / 1024 + " freeMem="+
                    freemem / 1024;

            changeStatusItemState(STATUS_TEXT, text);
            Debug.println(Debug.TYPE_GC, "Heap:" + text);
        }
    }

    /**
     * Returns true if the framework window is being closed. 
     * This API exists as a workaround to JFC bug #4119268 
     * in which action events are incorrectly sent to components
     * that appear underneath (Z order) menu items.
     * Such components should ignore their action event if framework is closing.
     */
    public boolean isClosing() {
	    return _isClosing;
    }
    
    /**
     * Closes the Framework window. If this is the last Framework window,
     * it exits the VM.
     */
    protected void closeFramework() {
        if (okToClose()) {
	    _isClosing = true;
	    savePreferences();
            if ((getJFrame() ==
                    UtilConsoleGlobals.getRootTopologyFrame()) &&
                    (UtilConsoleGlobals.getWindowCount() != 1)) {
                UtilConsoleGlobals.getRootTopologyFrame().setVisible(
                        false);
            } else {
                UtilConsoleGlobals.setClosingFrame(getJFrame());
                UtilConsoleGlobals.decrementWindowCount();
				
				// 352710: calling dispose() immediately causes spurious error
				//         "non-showing Component" messages from JFC
	            //         code in MenuSelectionManager.java
                SwingUtilities.invokeLater(new Runnable() {
                            public void run() {
                                getJFrame().dispose();
                            }
                    });
				
                int count = UtilConsoleGlobals.getWindowCount();
                if ((count == 0) || ((count == 1) &&
                        !(UtilConsoleGlobals.getRootTopologyFrame().
                        isVisible()))) {
                    System.exit(0);
                }
            }
        }
    }

    public void exitFramework() {
        if (okToClose()) {
            savePreferences();
            System.exit(0);
        }
    }

    protected boolean okToClose() {
        boolean okToClose = true;
        for (int i = 0; i < _pageList.length; i++) {
            try {
                _pageList[i].actionViewClosing(Framework.this);
            } catch (CloseVetoException exception) {
                okToClose = false;
            }
        }
        if (okToClose == false) {
            int value = SuiOptionPane.showConfirmDialog(getJFrame(),
                    i18n("dialog", "closetext"),
                    i18n("dialog", "closetitle"),
                    SuiOptionPane.YES_NO_OPTION,
                    SuiOptionPane.QUESTION_MESSAGE);
            if (value == SuiOptionPane.YES_OPTION) {
                okToClose = true;
            }
        }
        return okToClose;
    }

    class FileNewAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            if (_frameworkInitializer != null)
                new Framework(_frameworkInitializer);
        }
    }

    class NotYetImplemented implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            Debug.println(
                    "Framework.actionPerformed:Not Yet Implemented: " +
                    ((JMenuItem) e.getSource()).getText());
        }
    }

    class PreferencesAction implements ActionListener {
        private IPreferencesTab tabs[] = null;
        public void actionPerformed(ActionEvent e) {
            if(tabs == null)
            {
                Vector tabVector = new Vector();
                tabVector.addElement(new SettingsPreferencesTab());
                tabVector.addElement(new FontPreferencesTab());
                if(_frameworkInitializer instanceof FrameworkInitializer)
                {
                    FrameworkInitializer fi = (FrameworkInitializer)_frameworkInitializer;
                    int tabCount = fi.getPreferencesTabCount();
                    for(int i=0; i < tabCount; i++)
                    {
                        tabVector.addElement(fi.getPreferencesTab(i));
                    }
                }
                tabs = new IPreferencesTab[tabVector.size()];
                tabVector.copyInto(tabs);
            }
            PreferencesDialog d = new PreferencesDialog(getJFrame(), tabs);
            d.show();
        }
    }

    class TabChangeActionListener implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            AbstractButton button = (AbstractButton) e.getSource();
            _tabbedPane.setSelectedIndex(
                    _tabbedPane.indexOfTab(button.getText()));
        }
    }

    class StatusBarToggleAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            JCheckBoxMenuItem button = (JCheckBoxMenuItem) e.getSource();
            setStatusPanel(button.getState());
            _framePanel.validate();
            _framePanel.repaint();
        }
    }

    private void setBannerPanel(boolean b) {
        _isBannerBarVisible = b;
        if (_isBannerBarVisible) {
            _framePanel.add("North", _bannerPanel);
            initializeColors(getBannerBackground());
        } else {
            _framePanel.remove(_bannerPanel);
            initializeColors(getBackground());
        }

        _framePanel.setBorder(
                BorderFactory.createEmptyBorder(_isBannerBarVisible ?
                2 : VERT_WINDOW_INSET, HORIZ_WINDOW_INSET,
                _isStatusBarVisible ? 2 : VERT_WINDOW_INSET,
                HORIZ_WINDOW_INSET));
        Preferences p =
                _preferenceManager.getPreferences(PREFERENCES_GENERAL);
        p.set(PREFERENCE_SHOW_BANNER, _isBannerBarVisible);
    }

    private void setStatusPanel(boolean b) {
        _isStatusBarVisible = b;
        if (_isStatusBarVisible)
            _framePanel.add("South", _statusPanel);
        else
            _framePanel.remove(_statusPanel);

        _framePanel.setBorder(
                BorderFactory.createEmptyBorder(_isBannerBarVisible ?
                2 : VERT_WINDOW_INSET, HORIZ_WINDOW_INSET,
                _isStatusBarVisible ? 2 : VERT_WINDOW_INSET,
                HORIZ_WINDOW_INSET));
        Preferences p =
                _preferenceManager.getPreferences(PREFERENCES_GENERAL);
        p.set(PREFERENCE_SHOW_STATUS, _isStatusBarVisible);
    }

    class ShowTopologyButtonAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            JFrame f = UtilConsoleGlobals.getRootTopologyFrame();

            if (f == null) {
                try {
                    setBusyCursor(true);
                    f = Console.createTopologyFrame();
                }
                finally {
                    setBusyCursor(false);
                }
            }

            if (f != null) {
                f.setVisible(true);
                f.toFront();
            }
        }
    }

    class BannerBarToggleAction implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            JCheckBoxMenuItem button = (JCheckBoxMenuItem) e.getSource();
            setBannerPanel(button.getState());
            _framePanel.validate();
            _framePanel.repaint();
        }
    }

    class TabChangeListener implements ChangeListener {
        int _previousIndex = -1;

        public void stateChanged(ChangeEvent ev) {
            int index = _tabbedPane.getSelectedIndex();
            if (index == -1)
                return;

            if (_isPageInitialized[index] == false) {
                _isPageInitialized[index] = true;
                IPage page = (IPage)_tabbedPane.getComponentAt(index);
                Cursor savedCursor = Framework.this.getCursor();
                Framework.this.setCursor(
                        Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
                page.initialize(Framework.this);
                Framework.this.setCursor(savedCursor);
            }

            if (_previousIndex != -1)
                _pageList[_previousIndex].pageUnselected(Framework.this);

            if (_previousIndex != index) {
                _pageList[index].pageSelected(Framework.this);
                _previousIndex = index;
            }

            // Cause menu toggle item to be set to the current tab selection.
            // Basic algorithm: find the button at the index of the selected tab
            //                  and set its selection to true.
            int count = -1;
            Enumeration toggleButtons = _tabButtonGroup.getElements();
            AbstractButton button = null;
            while (count != index) {
                if (toggleButtons.hasMoreElements()) {
                    button = (AbstractButton) toggleButtons.nextElement();
                    count++;
                } else {
                    break;
                }
            }
            if (button != null) {
                button.setSelected(true);
            }
        }
    }
}
