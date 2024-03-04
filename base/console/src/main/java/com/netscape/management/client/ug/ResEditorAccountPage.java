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

import java.awt.Color;
import java.awt.Cursor;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Window;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Observable;
import java.util.Observer;
import java.util.Vector;

import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.SwingUtilities;
import javax.swing.event.ListSelectionEvent;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableColumn;

import com.netscape.management.client.util.ClassLoaderUtil;
import com.netscape.management.client.util.Debug;
import com.netscape.management.client.util.GridBagUtil;
import com.netscape.management.client.util.Help;
import com.netscape.management.nmclf.SuiLookAndFeel;
import com.netscape.management.nmclf.SuiTable;


/**
 * The Resource Editor is presented to the administrator as a series of
 * editable pages. Each page contains different information for the same
 * resource. For example, the "user" resource may contain a page for the
 * user's general information, i.e. name, unique ID, and phone. It may
 * also contain a separate page which describes all services the user is
 * licensed to use. Each page is a plugin to the Resource Editor, and it
 * must implement the IResourceEditorPage interface.
 * <p>
 * ResEditorAccountPage displays which products the user or group has
 * been granted an account.
 *
 * @see IResourceEditorPage
 * @see ResourceEditor
 */
public class ResEditorAccountPage extends JPanel implements IResourceEditorPage,
Observer {
    PickerEditorResourceSet _resource = new PickerEditorResourceSet();
    SuiTable _table;
    static Hashtable _HTAccountPlugin = null;
    Hashtable _HTPlugin = null; // for local instance plugin
    Vector _vCurrentSelected;
    AccountPageTableModel _tableModel;
    ResourcePageObservable _observable;
    Vector _vKey;

    private String ID;

    /**
    * Constructor
    */
    public ResEditorAccountPage() {
        super(true);

        _vCurrentSelected = new Vector();

        ID = _resource.getString("AccountPage","ID");
    }

    /**
     * Implements the Observer interface. Updates the view when notified.
     *
     * @param o    the observable object
     * @param arg  the attribute to update
     */
    public void update(Observable o, Object arg) {
        if (o instanceof ResourcePageObservable) {
            // Causes refresh problem in CALPage and OUPage
            String sAttrName = (String) arg;
            if ((sAttrName != null) &&
                    (sAttrName.toLowerCase().equals("objectclass"))) {
                // set checkbox
                checkUpdate((ResourcePageObservable) o);
            }
        }
    }

    void checkUpdate(ResourcePageObservable observable) {
        Vector vObjectClasses = observable.get("objectclass");
        for (int i = 0; i < vObjectClasses.size(); i++) {
            String sTmp = (String) vObjectClasses.elementAt(i);
            vObjectClasses.setElementAt(sTmp.toLowerCase(), i);
        }

        _vCurrentSelected = new Vector();
        // we have a list of plugin let continue.
        Enumeration eKey = _vKey.elements();
        while (eKey.hasMoreElements()) {
            // try to load the class
            String sDisplayName = (String) eKey.nextElement();
            IResourceEditorAccPage o =
                    (IResourceEditorAccPage)_HTPlugin.get(sDisplayName);
            String sObjectClassName[] = o.
                    getAssociatedObjectClass();
            if (sObjectClassName != null) {
                for (int i = 0; i < sObjectClassName.length; i++) {
                    if (vObjectClasses.contains(
                            sObjectClassName[i].toLowerCase())) {
                        _vCurrentSelected.addElement(sDisplayName);
                        break;
                    }
                }
            }
        }
        _tableModel.setSelected(_vCurrentSelected);
        _table.repaint();
    }

    /**
      * Implements the IResourceEditorPage interface.
     * Initializes the page with context information. It will be called once
     * the page is added to resource editor.
      *
      * @param observable  the observable object
      * @param parent      the resource editor container
      */
    public void initialize(ResourcePageObservable observable,
            ResourceEditor parent) {
        _observable = observable;

        if (_HTAccountPlugin == null) {
            // build the account page plugin table
            _HTAccountPlugin = ResourceEditor.getAccountPlugin();
        }

        Vector vObjectClasses = observable.get("objectclass");
        for (int i = 0; i < vObjectClasses.size(); i++) {
            String sTmp = (String) vObjectClasses.elementAt(i);
            vObjectClasses.setElementAt(sTmp.toLowerCase(), i);
        }
        Enumeration eObjectClasses = vObjectClasses.elements();
        Vector vAccountAvail = new Vector();
        while (eObjectClasses.hasMoreElements()) {
            String sObjectClass = (String) eObjectClasses.nextElement();
            Vector vPlugins = (Vector)_HTAccountPlugin.get(sObjectClass);
            if (vPlugins != null) {
                Enumeration ePlugins = vPlugins.elements();
                while (ePlugins.hasMoreElements()) {
                    String sPlugin = (String) ePlugins.nextElement();
                    if (!vAccountAvail.contains(sPlugin)) {
                        vAccountAvail.addElement(sPlugin);
                    }
                }
            }
        }

        // we have a list of plugin let continue.
        Enumeration eAccountAvail = vAccountAvail.elements();
        _HTPlugin = new Hashtable();
        _vKey = new Vector();
        while (eAccountAvail.hasMoreElements()) {
            // try to load the class
            String sClassName = (String) eAccountAvail.nextElement();
            Class c = ClassLoaderUtil.getClass(parent.getConsoleInfo(),
                    sClassName);
            if (c != null) {
                try {
                    Object o = c.newInstance();
                    if (o instanceof IResourceEditorAccPage) {
                        String sDisplayName = ((IResourceEditorAccPage) o).
                                getAccountDisplayName();
                        String sObjectClassName[] =
                                ((IResourceEditorAccPage) o).
                                getAssociatedObjectClass();
                        if (sObjectClassName != null) {
                            for (int i = 0;
                                    i < sObjectClassName.length; i++) {
                                if (vObjectClasses.contains(
                                        sObjectClassName[i]
                                        .toLowerCase())) {
                                    _vCurrentSelected.addElement(
                                            sDisplayName);
                                    ((IResourceEditorAccPage) o).
                                            addAccount(_observable);
                                    break;
                                }
                            }
                            _HTPlugin.put(sDisplayName, o);
                            _vKey.addElement(sDisplayName);
                        }
                    }
                } catch (Exception eCannotCreate) {
                    Debug.println(0,
                            "ResEditorAccountPage: Cannot create instance for:"+
                            sClassName);
                }
            }
        }
        // okay, we have all the classes... get the name and associated Object Classes
        _tableModel = new AccountPageTableModel(this, _vKey, _vCurrentSelected);

        // set the layout
        removeAll();

        setLayout(new GridBagLayout());

        JLabel label = new JLabel(_resource.getString("AccountPage","text"));
        GridBagUtil.constrain(this, label, 0, 0,
                GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.VERT_WINDOW_INSET,
                SuiLookAndFeel.HORIZ_WINDOW_INSET, 0,
                SuiLookAndFeel.HORIZ_WINDOW_INSET);

        _table = new SuiTable(_tableModel);
        label.setLabelFor(_table);
        _table.setColumnSelectionAllowed(false);
        _table.setRowSelectionAllowed(false);
        _table.setShowGrid(false);
        TableColumn tc=_table.getColumn(_table.getColumnName(1));

        JScrollPane scrollpane = JTable.createScrollPaneForTable(_table);
        scrollpane.getViewport().setBackground(Color.white);
        GridBagUtil.constrain(this, scrollpane, 0, 1,
                GridBagConstraints.REMAINDER,
                GridBagConstraints.REMAINDER, 1.0, 1.0,
                GridBagConstraints.WEST, GridBagConstraints.BOTH, 0,
                SuiLookAndFeel.HORIZ_WINDOW_INSET,
                SuiLookAndFeel.VERT_WINDOW_INSET,
                SuiLookAndFeel.HORIZ_WINDOW_INSET);

        _table.repaint();

        if (_vKey.size() <= 0) {
            ID = null;
        }
    }


    /**
      * Implements the IResourceEditorPage interface.
     * Returns unique ID string which identifies the page.
      *
      * @return  unique ID for the page
      */
    public String getID() {
        return ID;
    }

    /**
     * Implements the IResourceEditorPage interface.
      * Handle some post save condition. This is called after the
      * information is saved and the object has been created in
      * the directory server.
      *
      * @param observable     the observable object
      * @return               true if save succeeded; false otherwise
      * @exception Exception
     */
    public boolean afterSave(ResourcePageObservable observable)
            throws Exception {
        return true;
    }

    /**
     * Implements the IResourceEditorPage interface.
      * Saves all modified information to the observable object
      *
      * @param observable     the observable object
      * @return               true if save succeeded; false otherwise
      * @exception Exception
     */
    public boolean save(ResourcePageObservable observable)
            throws Exception {
        return true;
    }

    /**
     * Implements the IResourceEditorPage interface.
      * Clears all information on the page.
     */
    public void clear() {
    }

    /**
     * Implements the IResourceEditorPage interface.
      * Resets information on the page.
     */
    public void reset() {
    }

    /**
     * Implements the IResourceEditorPage interface.
      * Sets default information on the page. Ignored.
     */
    public void setDefault() {
    }

    /**
     * Implements the IResourceEditorPage interface.
      * Specifies whether any information on the page has been modified.
      *
      * @return  true if some information has been modified; false otherwise
     */
    public boolean isModified() {
        return false;
    }

    /**
     * Implements the IResourceEditorPage interface.
      * Sets the modified flag for the page. Ignored.
      *
      * @param value  true or false
     */
    public void setModified(boolean value) {
    }

    /**
     * Implements the IResourceEditorPage interface.
      * Specifies whether the information on the page is read only.
      *
      * @return  true if some information has been modified; false otherwise
     */
    public boolean isReadOnly() {
        return false;
    }

    /**
     * Implements the IResourceEditorPage interface.
      * Sets the read only flag for the page. Ignored.
      *
      * @param value  true or false
     */
    public void setReadOnly(boolean value) {
    }

    /**
     * Implements the IResourceEditorPage interface.
      * Sets the enabled flag for the page. Ingored.
      *
      * @param value  true or false
     */
    public void setEnable(boolean value) {
    }

    /**
     * Implements the IResourceEditorPage interface.
      * Specifies whether all required information has been provided for
      * the page.
      *
      * @return  true if all required information has been provided; false otherwise
     */
    public boolean isComplete() {
        // always true
        return true;
    }

    /**
     * Implements the IResourceEditorPage interface.
      * Returns a brief name for the page. The name should reflect the
      * plugin page.
     */
    public String getDisplayName() {
        return ID;
    }

    /**
     * Handles notification of list selection events.
     *
     * @param event  the list selection event
     */
    public void valueChanged(ListSelectionEvent event) {
    }

    /**
     * Adds an account to the indicated plugin.
      *
      * @param sDisplayName  name of the account
     */
    public void addAccount(String sDisplayName) {
        Object o = _HTPlugin.get(sDisplayName);
        if (o != null) {
            ((IResourceEditorAccPage) o).addAccount(_observable);
        }
    }

    /**
     * Removes an account from the indicated plugin.
      *
      * @param sDisplayName  name of the account
     */
    public void removeAccount(String sDisplayName) {
        Object o = _HTPlugin.get(sDisplayName);
        if (o != null) {
            ((IResourceEditorAccPage) o).removeAccount(_observable);
        }
    }

    /**
     * Implements the IResourceEditorPage interface.
      * Displays help information for the page
     */
    public void help() {
        Help help = new Help(_resource);

        help.contextHelp("ug","ResEditorAccountPage");
    }
}


/**
  * AccountPageTableModel is used as the table model for the ResEditorAccountPage.
  */
class AccountPageTableModel extends AbstractTableModel {
    PickerEditorResourceSet _resource = new PickerEditorResourceSet();
    Vector _vName;
    Vector _vSelected;
    ResEditorAccountPage _parent;

    AccountPageTableModel(ResEditorAccountPage parent, Vector vName,
            Vector vSelected) {
        _vName = vName;
        _vSelected = vSelected;
        _parent = parent;
    }

    public void setSelected(Vector v) {
        _vSelected = v;
        fireTableDataChanged();
    }

    public int getColumnCount() {
        return 2;
    }

    public int getRowCount() {
        return _vName.size();
    }

    public Object getValueAt(int row, int col) {
        Object o = null;
        switch (col) {
        case 0:
            o = _vName.elementAt(row);
            break;
        case 1:
            o = Boolean.valueOf(_vSelected.contains(_vName.elementAt(row)));
            break;
        }
        return o;
    }

    public Class getColumnClass(int col) {
        return (col != 0) ? Boolean.class : super.getColumnClass(col);
            }

    public boolean isCellEditable(int row, int col) {
        return (col != 0);
    }

    public void setValueAt(Object aValue, int row, int col) {
        if (col != 0) {
            final String sName = (String)_vName.elementAt(row);
            Boolean fSelected = (Boolean) aValue;
            if (col == 1) {
                boolean fAlreadyThere = _vSelected.contains(sName);
                if (fAlreadyThere) {
                    if (!fSelected.booleanValue()) {
                        _vSelected.removeElement(sName);
                        _parent.removeAccount(sName);
                        _parent.setModified(true);
                    }
                } else {
                    if (fSelected.booleanValue()) {
                        _vSelected.addElement(sName);
                        // Add account in the background
                        SwingUtilities.invokeLater( new Runnable() {
                            public void run() {
                                Window w = (Window)
                                    SwingUtilities.getAncestorOfClass(Window.class, _parent);
                                if (w!=null) {
                                    w.setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
                                }
                                _parent.addAccount(sName);
                                _parent.setModified(true);
                                if (w!=null) {
                                    w.setCursor(Cursor.getDefaultCursor());
                                }

                            }
                        });
                    }
                }
            }
        }
    }

    public String getColumnName(int col) {
        String sReturn = "";

        switch (col) {
        case 0:
            sReturn = _resource.getString("AccountPage","product");
            break;
        case 1:
            sReturn = _resource.getString("AccountPage","install");
            break;
        }
        return sReturn;
    }

    public Vector getSelected() {
        return _vSelected;
    }
}
