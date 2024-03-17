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

import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Component;
import java.awt.Container;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Observable;
import java.util.Observer;
import java.util.Vector;

import javax.swing.BorderFactory;
import javax.swing.DefaultListModel;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.SwingUtilities;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

import com.netscape.management.client.console.ConsoleInfo;
import com.netscape.management.client.util.AbstractDialog;
import com.netscape.management.client.util.Debug;
import com.netscape.management.client.util.GridBagUtil;
import com.netscape.management.client.util.ModalDialogUtil;
import com.netscape.management.client.util.ResourceSet;
import com.netscape.management.nmclf.SuiListCellRenderer;
import com.netscape.management.nmclf.SuiLookAndFeel;
import com.netscape.management.nmclf.SuiOptionPane;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPDN;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;

class TabListCellRender extends SuiListCellRenderer
{
    public Component getListCellRendererComponent(
                                                  JList list,
                                                  Object value,
                                                  int index,
                                                  boolean isSelected,
                                                  boolean cellHasFocus)
    {
        IResourceEditorPage p = (IResourceEditorPage)value;
        return super.getListCellRendererComponent(list,p.getDisplayName(),index,isSelected,cellHasFocus);
    }
}

/**
 * ResourceEditor is a general dialog for editing resources such as users,
 * groups, and organizational units. The resource editor dialog contains
 * one or more "pages" of editable fields. Each editable page is a class
 * which implements the IResourceEditorPage interface. Depending on the
 * objectclasses that are passed in to the constructor of this class,
 * different pages get loaded for editing.
 *
 * ResourceEditor can be used for either editing an existing entry or
 * creating a new entry. It can also be displayed as a modal dialog or as
 * a non-modal dialog.
 *
 * @see IResourceEditorPage
 */
public class ResourceEditor extends AbstractDialog implements ActionListener, ListSelectionListener,
Observer {
    static Hashtable _ResourceEditorExtension;
    static Hashtable _DeleteResourceEditorExtension;
    static Hashtable _AccountPlugin;
    static String _sUniqueAttribute = "uid";
    static String _sUserIDFormat = "";
    static String _sUserRDNComponent = "uid";
    static String _sGroupRDNComponent = "cn";
    static Hashtable _hNewObjectClasses = new Hashtable();

    public static final String KEY_NEW_OU_OBJECTCLASSES = "newOUObjectClasses";
    public static final String KEY_NEW_GROUP_OBJECTCLASSES = "newGroupObjectClasses";
    public static final String KEY_NEW_USER_OBJECTCLASSES = "newUserObjectClasses";

    ResourceEditorActionPane _actionPane;
    JPanel _titlePane;
    JPanel _plugin;
    JSplitPane _splitPane;

    CardLayout _cardLayout;
    JPanel _pagePanel;
    DefaultListModel _tabListModel;
    JList _tabListbox;
    JScrollPane _tabListScrollPane;

    ResourcePageObservable _observableLDAPEntry;
    LDAPEntry _ldapEntry;
    Object _advancedOpt;

    boolean _newUser;
    JFrame _parent;
    ConsoleInfo _info;
    ResourceSet _resource = new ResourceSet("com.netscape.management.client.ug.PickerEditorResource");
    boolean _fSaveOK = false;

    Hashtable _oldClassHashtable;
    SearchResultPanel _resultPanel = null;


    /**
     * Constructor for creating a new object.
     *
     * @param parent           the parent component for the new dialog
     * @param info             the session info, such as LDAP server connection
     * @param objectClassList  the objectclasses which determine the editable pages to load
     * @param sCreatedLocDN    the LDAP object under which to create this new object
     */
    public ResourceEditor(JFrame parent, ConsoleInfo info,
                          Vector objectClassList, String sCreatedLocDN) {
        super(parent);
        _parent = parent;
        _newUser = true;

        init(info, true, objectClassList, sCreatedLocDN);
    }

    /**
     * Constructor for creating a new object which takes an additional
     * parameter used to display the new object after it has been saved.
     *
     * @param parent           the parent component for the new dialog
     * @param info             the session info, such as LDAP server connection
     * @param objectClassList  the objectclasses which determine the editable pages to load
     * @param sCreatedLocDN    the LDAP object under which to create this new object
     * @param resultPanel      the SearchResultPanel to display the result
     */
    public ResourceEditor(JFrame parent, ConsoleInfo info,
                          Vector objectClassList, String sCreatedLocDN,
                          SearchResultPanel resultPanel) {
        super(parent);
        _parent = parent;
        _newUser = true;
        _resultPanel = resultPanel;

        init(info, true, objectClassList, sCreatedLocDN);
    }

    /**
     * Constructor for editing an existing object.
     *
     * @param parent  the parent component for the new dialog
     * @param info    the session info, such as LDAP server connection
     * @param entry   the LDAP entry contain all user or group information
     */
    public ResourceEditor(JFrame parent, ConsoleInfo info,
                          LDAPEntry entry) {
        super(parent);
        _parent = parent;
        _ldapEntry = entry;
        _newUser = false;

        init(info, false, entry, null);
    }

    /**
     * Constructor for editing an existing object which takes an additional
     * parameter used to display the edited object after it has been saved.
     *
     * @param parent       the parent component for the new dialog
     * @param info         the session info, such as LDAP server connection
     * @param entry        LDAP entry contain all user or group information
     * @param resultPanel  the SearchResultPanel where the result will go
     */
    public ResourceEditor(JFrame parent, ConsoleInfo info,
                          LDAPEntry entry, SearchResultPanel resultPanel) {
        super(parent);
        _parent = parent;
        _ldapEntry = entry;
        _newUser = false;
        _resultPanel = resultPanel;

        init(info, false, entry, null);
    }


    /**
     * Initializes the dialog.
     *
     * @param info   the session info, such as LDAP server connection
     * @param isNew  whether the object to edit needs to be created
     * @param obj    either the objectclasses Vector or the LDAPEntry
     * @param baseDN Base DN of the entry to be created
     */
    void init(ConsoleInfo info, boolean isNew, Object obj, String baseDN) {
        _info = info;

        if (isNew) {
            _observableLDAPEntry =
                      new ResourcePageObservable(info, null, isNew);
            _observableLDAPEntry.setObjectClass((Vector) obj);
            setTitle(_resource.getString("resourceEditor","NewUserTitle"));
        } else {
            _observableLDAPEntry =
                      new ResourcePageObservable(info, (LDAPEntry) obj,
                                                 isNew);
            setTitle(_resource.getString("resourceEditor","EditUserTitle"));
        }
        if (baseDN != null) {
            _observableLDAPEntry.setCreateBaseDN(baseDN);
        }
        _observableLDAPEntry.addObserver(this);

        _titlePane = new JPanel(new BorderLayout());
        _actionPane = new ResourceEditorActionPane(this);

        _cardLayout = new CardLayout();
        _pagePanel = new JPanel(_cardLayout);
        _pagePanel.setBorder(BorderFactory.createEtchedBorder());

        _tabListModel = new DefaultListModel();
        _tabListbox = new JList(_tabListModel);
        _tabListbox.getAccessibleContext().setAccessibleDescription(_resource.getString("resourceEditor","navigator_tt"));

        _tabListbox.setCellRenderer(new TabListCellRender());
        _tabListbox.addListSelectionListener(this);
        _tabListScrollPane = new JScrollPane(_tabListbox);
        _tabListScrollPane.setPreferredSize(new Dimension(100,200));
        _splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, _tabListScrollPane, _pagePanel);
        _splitPane.setDividerLocation((int)_tabListScrollPane.getPreferredSize().getWidth());
        _splitPane.setBorder(BorderFactory.createEmptyBorder());
        setMinimumSize(640, 480);

        // get the object class to java class association
        // setup plugin
        setupPlugin(obj);

        if (_tabListModel.getSize()==0)
        {
            addPage(new DefaultResEditorPage());
        }

        setDisplay();
    }

    /**
     * Determines the IResourceEditorPage plugins to load
     *
     * @param obj  either the objectclasses Vector or the LDAPEntry
     */
    void setupPlugin(Object obj) {
        Hashtable htable = getResourceEditorExtension();
        Enumeration eObjectClass = null;
        if (obj instanceof LDAPEntry) {
            LDAPEntry entry = (LDAPEntry) obj;
            LDAPAttribute attribute = entry.getAttribute("ObjectClass");
            eObjectClass = attribute.getStringValues();
        } else {
            eObjectClass = ((Vector) obj).elements();
        }

        // clear up the old class hashtable
        if (_oldClassHashtable != null) {
            Enumeration eOldPage = _oldClassHashtable.elements();
            while (eOldPage.hasMoreElements()) {
                Object oldPage = eOldPage.nextElement();
                if(oldPage instanceof Observer) {
                    _observableLDAPEntry.deleteObserver((Observer)oldPage);
                }
            }
        }

        String sSelectedTitle = (_tabListbox.getSelectedIndex()!=(-1))?
                  ((IResourceEditorPage)_tabListbox.getSelectedValue()).getID():"";
        _tabListModel.removeAllElements();

        Hashtable hAddedClass = new Hashtable();

        boolean fIsUserObject = false;
        boolean fIsGroupObject = false;
        int index = 0;
        int selectedPos = 0;

        while (eObjectClass.hasMoreElements()) {
            String sObjectClassName =
                      ((String) eObjectClass.nextElement()).toLowerCase();
            if (sObjectClassName.equals("person")) {
                fIsUserObject = true;
            } else if (sObjectClassName.equals("groupofuniquenames")) {
                fIsGroupObject = true;
            }
            Vector vClass = (Vector) htable.get(sObjectClassName);
            if (vClass != null) {
                Enumeration eClass = vClass.elements();
                while (eClass.hasMoreElements()) {
                    String sClassName = "";
                    try {
                        Class c = (Class) eClass.nextElement();
                        sClassName = c.getName();
                        if (hAddedClass.get(sClassName) == null) {
                            Object o = null;
                            if ((_oldClassHashtable == null) ||
                                (o = _oldClassHashtable.get(
                                                            sClassName)) == null) {
                                o = c.newInstance();
                                if (o instanceof IResourceEditorPage) {
                                    hAddedClass.put(sClassName, o);
                                    if (addPage((IResourceEditorPage) o)) {
                                        if (((IResourceEditorPage) o).
                                            getID().equals(sSelectedTitle)) {
                                            selectedPos = index;
                                        }
                                        index++;
                                    }
                                } else {
                                    Debug.println(sClassName + " is not an instance of IResourceEditorPage.");
                                }
                            } else {
                                IResourceEditorPage pageEditor =
                                          (IResourceEditorPage) o;
                                if (pageEditor.getID() != null) {
                                    if (pageEditor instanceof Observer) {
                                        _observableLDAPEntry.addObserver((Observer) pageEditor);
                                    }
                                    _tabListModel.addElement(pageEditor);
                                    if (pageEditor.getID().equals(
                                                                  sSelectedTitle)) {
                                        selectedPos = index;
                                    }
                                    index++;
                                }
                                hAddedClass.put(sClassName, o);
                            }
                        }
                    } catch (Exception e) {
                        Debug.println(0,
                                      "Cannot create class: "+sClassName);
                    }
                }
            }
        }
        _tabListbox.setSelectedIndex(selectedPos);

        _oldClassHashtable = hAddedClass;


        // only add title page if needed
        if (fIsUserObject) {
            ResEditorUserTitlePage titlePage =
                      new ResEditorUserTitlePage(_observableLDAPEntry);
            setTitlePanel(titlePage);
        } else if (fIsGroupObject) {
            ResEditorGroupTitlePage titlePage =
                      new ResEditorGroupTitlePage(_observableLDAPEntry);
            setTitlePanel(titlePage);
        } else {
            ResEditorOUTitlePage titlePage =
                      new ResEditorOUTitlePage(_observableLDAPEntry);
            setTitlePanel(titlePage);
        }
    }


    /**
     * Performs layout of components for the dialog
     */
    void setDisplay() {
        Container c = getContentPane();
        c.setLayout(new GridBagLayout());
        GridBagUtil.constrain(c, _titlePane, 0, 0,
                              GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                              GridBagConstraints.NORTHWEST,
                              GridBagConstraints.HORIZONTAL, 0, 0, 0, 0);

        GridBagUtil.constrain(c, _splitPane, 0, 1,
                              GridBagConstraints.REMAINDER, 1, 1.0, 1.0,
                              GridBagConstraints.CENTER, GridBagConstraints.BOTH,
                              SuiLookAndFeel.SEPARATED_COMPONENT_SPACE, 0, 0, 0);

        GridBagUtil.constrain(c, _actionPane, 0, 2,
                              GridBagConstraints.REMAINDER,
                              GridBagConstraints.REMAINDER, 1.0, 0.0,
                              GridBagConstraints.SOUTHWEST, GridBagConstraints.HORIZONTAL,
                              SuiLookAndFeel.SEPARATED_COMPONENT_SPACE, 0, 0, 0);
    }

    /**
     * Sets the index attribute
     *
     * @param attr  the index attribute
     */
    public void setIndexAttribute(String attr) {
        _observableLDAPEntry.setIndexAttribute(attr);
    }

    /**
     * Gets the LDAPEntry object. This method is called to get the updated
     * LDAPEntry object after all plugins have been saved.
     *
     * @return  the LDAPEntry object
     */
    public LDAPEntry getLDAPEntry() {
        return _ldapEntry;
    }

    /**
     * Gets the observable object
     *
     * @return  the ResourcePageObservable object
     */
    public ResourcePageObservable getLDAPObservable() {
        return _observableLDAPEntry;
    }

    /**
     * Array of the characters that may be escaped in a DN.
     */
    final char[] ESCAPED_CHAR = {',', '+', '"', '\\', ';'};
    boolean isMultiValuedRDN(String rdn) {
        if (rdn == null)
            return false;

        StringBuffer buffer = new StringBuffer(rdn);
        int i = 0;
        boolean openQuotes = false;
        while (i < buffer.length()) {
            // Check for escaped characters
            if (buffer.charAt(i) == '\\') {
                char c = buffer.charAt(i+1);
                for (int j=0; j<ESCAPED_CHAR.length; j++) {
                    if (c == ESCAPED_CHAR[j]) {
                        i++;
                        break;
                    }
                }
            } else if (buffer.charAt(i) == '"') {
                // this is the second "
                if (openQuotes) {
                    openQuotes = false;
                } else
                    // this is the first "
                    openQuotes = true;
            } else if (buffer.charAt(i) == '+') {
                // A plus sign which is not escaped and not quoted
                if (!openQuotes) {
                    return true;
                }
            }
            i++;
        }
        return false;
    }

    public void valueChanged(ListSelectionEvent e)
    {
        if (_tabListModel.size() != 0) {
            IResourceEditorPage o = (IResourceEditorPage)_tabListbox.getSelectedValue();
            if (Debug.isEnabled()) {
                Debug.println("ResourceEditor.valueChanged: o=" + o);
            }

            // If setupPlugin has been called, the tabListbox is  removed of all elements
            // in which case this method is called with a null page.
            if (o != null) {
                _cardLayout.show(_pagePanel,o.getID());
            }
        } else {
            Debug.println("ResourceEditor.valueChanged: empty tab list");
        }
    }

    /**
     * Implements the ActionListener interface. Handles the button events from
     * the ResourceEditorActionPane.
     *
     * @param e  the action event
     */
    public void actionPerformed(ActionEvent e) {
        JDialog d = (JDialog)SwingUtilities.getAncestorOfClass(JDialog.class, _actionPane);
        if (d != null) {
            d.setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
        }
        try {
            processEvent(e);
        }
        finally {
            if (d != null) {
                d.setCursor(Cursor.getDefaultCursor());
            }
        }
    }

    void processEvent(ActionEvent e) {
        if (e.getActionCommand().equals("Ok")) {
            //check if all page is complete

            for (int i = 0; i < _tabListModel.getSize(); i++) {
                if (!(((IResourceEditorPage)(_tabListModel.elementAt(i))).
                      isComplete())) {
                    _tabListbox.setSelectedIndex(i);
                    return;
                }
            }

            try {
                String[] rdns = LDAPDN.explodeDN( _observableLDAPEntry.getDN(), false );
                if ((rdns != null) && isMultiValuedRDN(rdns[0])) {
                    //pop up dialog, dn contain multi value rdn, so won't be able to modify.
                    SuiOptionPane.showMessageDialog(getFrame(),
                                                    _resource.getString("resourceEditor",
                                                                        "UnableToSaveRDNEntryText"),
                                                    _resource.getString("resourceEditor",
                                                                        "SaveErrorTitle"), SuiOptionPane.ERROR_MESSAGE);
                    return;
                }
                for (int i = 0; i < _tabListModel.getSize(); i++) {
                    ((IResourceEditorPage)(_tabListModel.elementAt(i))).
                              save(_observableLDAPEntry);
                }

                _ldapEntry = _observableLDAPEntry.save();
                for (int i = 0; i < _tabListModel.getSize(); i++) {
                    ((IResourceEditorPage)(_tabListModel.elementAt(i))).
                              afterSave(_observableLDAPEntry);
                }
                // If the ResourceEditor has been created with the SearchResultPanel,
                // display the search result of the current object. Good to show feedback
                // to the user for the object that has been created or edited.
                _ldapEntry = _observableLDAPEntry._entry;
                if (_resultPanel != null && _ldapEntry != null) {
                    /*_resultPanel.removeAllElements();
                       _resultPanel.addElement(_ldapEntry);*/
                    if ((_resultPanel.getListCount() <= 0) ||
                        (_resultPanel.getSelectedRowCount() <= 0)) {
                        _resultPanel.addElement(_ldapEntry);
                    } else {
                        _resultPanel.updatedSelectedItem(_ldapEntry);
                    }
                }
                _fSaveOK = true;
            }
            catch (Exception err) {
                LDAPException lex = (err instanceof LDAPException) ? (LDAPException)err : null;
                if (Debug.isEnabled()) {
                    if (! (err instanceof LDAPException)) {
                        err.printStackTrace();
                    }
                }
                SuiOptionPane.showMessageDialog(getFrame(),
                                                _resource.getString("resourceEditor",
                                                                    "SaveErrorText") + err,
                                                _resource.getString("resourceEditor",
                                                                    "SaveErrorTitle"), SuiOptionPane.ERROR_MESSAGE);
                if (Debug.isEnabled()) {
                    err.printStackTrace();
                }
                ModalDialogUtil.sleep();
                if ((lex != null) && (lex.getLDAPResultCode() == ResourcePageObservable.NEW_ENTRY_TIMEOUT)) {
	                super.setVisible(false);
                }
                return;
            }
            super.setVisible(false);
        }
        else if (e.getActionCommand().equals("Cancel")) {
            super.setVisible(false);
        } else if (e.getActionCommand().equals("advanced")) {

            // Pass the current values to the advanced dialog
            try {
                for (int i = 0; i < _tabListModel.getSize(); i++) {
                    ((IResourceEditorPage)(_tabListModel.elementAt(i))).
                              save(_observableLDAPEntry);
                }
            }
            catch (Exception err) {
                Debug.println("ResourceEditor.actionPerformed=advanced " + err);
            }

            if (((IResEditorAdvancedOpt)_advancedOpt).run(_info,
                                                          _observableLDAPEntry)) {
                // reload the value
                for (int i = 0; i < _tabListModel.getSize(); i++) {
                    IResourceEditorPage pageEditor = (IResourceEditorPage)
                              _tabListModel.elementAt(i);
                    pageEditor.initialize(_observableLDAPEntry, this);
                }
            }
        } else if (e.getActionCommand().equals("help")) {
            Component c = (Component)_tabListbox.getSelectedValue();
            if (c instanceof IResourceEditorPage) {
                ((IResourceEditorPage) c).help();
            }
        }
    }


    /**
     * Gets the plugin for the specified index. The index starts from 1.
     *
     * @param  index  the index for the requested plugin
     * @return        the IResourceEditorPage object
     */
    public IResourceEditorPage getPage(int index) {
        IResourceEditorPage page;
        try {
            page = (IResourceEditorPage)
                      (_tabListModel.elementAt(index - 1));
        } catch (ArrayIndexOutOfBoundsException e) {
            Debug.println(0, "ResourceEditor.getPage: array index out of bounds exception");
            page = null;
        }
        return page;
    }


    /**
     * Gets the count of all plugins loaded.
     *
     * @return  the plugin count
     */
    public int getPageCount() {
        return _tabListModel.getSize();
    }


    /**
     * Adds a new plugin to the dialog.
     *
     * @param pageEditor  the plugin to add
     */
    public boolean addPage(IResourceEditorPage pageEditor) {
        boolean fAdd = false;

        pageEditor.initialize(_observableLDAPEntry, this);

        if (pageEditor instanceof Component) {
            if (pageEditor.getID() != null) {
                _tabListModel.addElement(pageEditor);
                _pagePanel.add((Component)pageEditor, pageEditor.getID());
                fAdd = true;
                if (pageEditor instanceof Observer) {
                    _observableLDAPEntry.addObserver(
                                                     (Observer) pageEditor);
                }
            }
        }
        return fAdd;
    }


    /**
     * Delete the plugin at the specified index. The index starts from 1.
     *
     * @param index  the plugin to delete
     */
    public void deletePage(int index) {
        if (index <= getPageCount() && index > 0) {
            Component c = (Component)_tabListModel.elementAt(index-1);
            _tabListModel.removeElementAt(index-1);
            _cardLayout.removeLayoutComponent(c);
        }
    }


    /**
     * Enables or disables the plugin at the specified index. The index
     * starts from 1.
     *
     * @param index  the plugin to enable/disable
     * @param value  plugin is enabled if true and disabled if false
     */
    public void setPageEnable(int index, boolean value) {
        try {
            if (index > getPageCount() || index < 1) {
                Debug.println(
                              "ResourceEditor.setPageEnable: invalid page: " +
                              index);
                return;
            }
            IResourceEditorPage page;
            page = (IResourceEditorPage)
                      (_tabListModel.elementAt(index - 1));
            page.setEnable(value);
        } catch (ArrayIndexOutOfBoundsException e) {
            Debug.println(0, "ResourceEditor.java : setPageEnable : Array out of bound.");
        }
    }


    /**
     * Changes all plugins to be editable or not
     *
     * @param value  all plugins are editable if true and read only if false
     */
    public void setReadOnly(boolean value) {
        try {
            IResourceEditorPage page;
            int pageCount = getPageCount();
            for (int i = 0; i < pageCount; i++) {
                page = (IResourceEditorPage)(_tabListModel.elementAt(i));
                page.setReadOnly(value);
            }
        } catch (ArrayIndexOutOfBoundsException e) {
            Debug.println(0, "ResourceEditor.java : setReadOnly : Array out of bound...");
        }
    }


    /**
     * Sets the title panel
     *
     * @param titlePane  the new title panel to display
     */
    public void setTitlePanel(JPanel titlePane) {
        if (titlePane != _titlePane) {
            if (_titlePane.getComponentCount() == 1) {
                _titlePane.remove(0);
            }
            if (titlePane != null) {
                _titlePane.add("North", titlePane);
                if (titlePane instanceof Observer) {
                    _observableLDAPEntry.addObserver((Observer) titlePane);
                }
                validate();
                repaint();
            }
        }
    }

    /**
     * Gets the title panel
     *
     * @return  the title panel
     */
    public JPanel getTitlePanel() {
        if (_titlePane.getComponentCount() == 1) {
            return (JPanel)_titlePane.getComponent(0);
        }
        return null;
    }

    /**
     * @deprecated  Use AbstractDialog.showModal().
     * @see AbstractDialog#showModal()
     */
    @Deprecated
    public boolean showModally() {
        super.showModal();
        return _fSaveOK;
    }


    /**
     * Gets the status of the save operation
     *
     * @return  true if saved and false if failed
     */
    public boolean getSaveStatus() {
        return _fSaveOK;
    }


    /**
     * Gets the parent component of this dialog
     *
     * @return  the parent component of this dialog
     */
    public JFrame getFrame() {
        return _parent;
    }


    /**
     * Gets the session info for this dialog
     *
     * @return  the session info for this dialog
     */
    public ConsoleInfo getConsoleInfo() {
        return _info;
    }


    /**
     * Registers the handler for the advanced option. The advanced button
     * becomes available in the button panel.
     *
     * @param opt  the handler for the advanced option
     */
    public void registerAdvancedOption(IResEditorAdvancedOpt opt) {
        _advancedOpt = opt;
        String buttonText = opt.getButtonText();
        if ((buttonText != null) && (buttonText != "")) {
            _actionPane.setAdvancedText(buttonText);
        }
        _actionPane.enableAdvanced(true);
    }

    /**
     * Implements the Observer interface
     */
    public void update(Observable o, Object arg) {
        if (Debug.isEnabled()) {
            Debug.println("ResourceEditor.update: o=" + o + " arg=" + arg);
        }
        if (o instanceof ResourcePageObservable) {
            // Causes refresh problem in CALPage and OUPage
            String sAttrName = (String) arg;
            if ((sAttrName != null) &&
                (sAttrName.toLowerCase().equals("objectclass"))) {
                // refresh the objectclass list
                ((ResourcePageObservable)o).syncObjectClassList();
                // update the plugin
                setupPlugin(((ResourcePageObservable) o).get("objectclass"));
            }
        }
    }

    /**
     * @deprecated  helpInvoked is no longer an abstract method. Morever, it is handled
     *              in the actionPerformed method.
     * @see AbstractDialog#helpInvoked()
     * @see #actionPerformed(ActionEvent)
     */
    @Deprecated
    public void helpInvoked() {
        System.out.println("ResourceEditor: Help Not Implemented");
    }


    /**
     * Sets the unique attribute.
     *
     * @param h  the unique attribute
     */
    static public void setUniqueAttribute(String s) {
        _sUniqueAttribute = s;
    }

    /**
     * Returns the unique attribute.
     *
     * @return  the unique attribute
     */
    static public String getUniqueAttribute() {
        return _sUniqueAttribute;
    }

    /**
     * Sets the user ID format.
     *
     * @param h  the user ID format
     */
    static public void setUserIDFormat(String s) {
        _sUserIDFormat = s;
    }

    /**
     * Returns the user ID format.
     *
     * @return  the user ID format
     */
    static public String getUserIDFormat() {
        return _sUserIDFormat;
    }

    /**
     * Sets the user RDN component.
     *
     * @param h  the user RDN component
     */
    static public void setUserRDNComponent(String s) {
        _sUserRDNComponent = s;
    }

    /**
     * Returns the user RDN component.
     *
     * @return  the user RDN component
     */
    static public String getUserRDNComponent() {
        return _sUserRDNComponent;
    }

    /**
     * Sets the group RDN component.
     *
     * @param h  the group RDN component
     */
    static public void setGroupRDNComponent(String s) {
        _sGroupRDNComponent = s;
    }

    /**
     * Returns the group RDN component.
     *
     * @return  the group RDN component
     */
    static public String getGroupRDNComponent() {
        return _sGroupRDNComponent;
    }

    /**
     * Sets the account plugin.
     *
     * @param h  the account plugin
     */
    static public void setAccountPlugin(Hashtable h) {
        _AccountPlugin = h;
    }

    /**
     * Returns the account plugin.
     *
     * @return  the account plugin
     */
    static public Hashtable getAccountPlugin() {
        return _AccountPlugin;
    }

    /**
     * Sets the new object classes.
     *
     * @param h  the new object classes
     */
    static public void setNewObjectClasses(Hashtable h) {
        _hNewObjectClasses = h;
    }

    /**
     * Returns the new object classes.
     *
     * @return  the new object classes
     */
    static public Hashtable getNewObjectClasses() {
        return _hNewObjectClasses;
    }

    /**
     * Sets the resource editor extension.
     *
     * @param h  the resource editor extension
     */
    static public void setResourceEditorExtension(Hashtable h) {
        _ResourceEditorExtension = h;
    }

    /**
     * Returns the resource editor extension.
     *
     * @return  the resource editor extension
     */
    static public Hashtable getResourceEditorExtension() {
        return _ResourceEditorExtension;
    }

    /**
     * Sets the delete resource editor extension.
     *
     * @param h  the delete resource editor extension
     */
    static public void setDeleteResourceEditorExtension(Hashtable h) {
        _DeleteResourceEditorExtension = h;
    }

    /**
     * Returns the delete resource editor extension.
     *
     * @return  the delete resource editor extension
     */
    static public Hashtable getDeleteResourceEditorExtension() {
        return _DeleteResourceEditorExtension;
    }
}
