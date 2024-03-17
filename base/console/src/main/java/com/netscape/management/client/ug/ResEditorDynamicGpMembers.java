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

import java.util.*;
import java.awt.*;
import java.awt.event.*;

import javax.swing.*;
import com.netscape.management.client.console.ConsoleInfo;
import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;


/**
 * ResEditorDynamicGpMembers is a plugin for the ResourceEditor. It is used
 * when editing group membership information. This page lets administrators
 * define the group membership using some dynamic criteria, such as matching
 * an attribute of a user to some value.
 *
 * @see IResourceEditorPage
 * @see ResourceEditor
 * @see ResEditorGroupMembers
 * @see DynamicQueryDlg
 */
public class ResEditorDynamicGpMembers extends JPanel implements IResourceEditorPage,
Observer, ActionListener {
    static final String ATTR_MEMBER_URL = "memberURL";

    PickerEditorResourceSet _resource = new PickerEditorResourceSet();
    ResourceEditor _resourceEditor;

    private String ID;

    boolean _isModified = false;
    boolean _isReadOnly = false;
    boolean _isEnable = true;

    ConsoleInfo _consoleInfo;

    JList _list;
    Vector _vList;
    Vector _vOldList;

    JButton _queryButton;
    JButton _addButton;
    JButton _removeButton;
    JButton _editButton;

    ResourcePageObservable _observable;


    /**
    * Constructor
    *
    * @param info  session information
    */
    public ResEditorDynamicGpMembers(ConsoleInfo consoleInfo) {
        super(true);

        _consoleInfo = consoleInfo;
        _vList = new Vector();

        ID = _resource.getString("dynamicGroupMember", "ID");

        JLabel label =
                new JLabel(_resource.getString("dynamicGroupMember", "label"));

        _list = new JList(_vList);
        label.setLabelFor(_list);
        JScrollPane scrollPane = new JScrollPane(_list);
        scrollPane.setBorder(UIManager.getBorder("Table.scrollPaneBorder"));

        //_queryButton = new JButton( resource.getString("DynamicGroup","QueryButton"));
        //_queryButton.addActionListener(this);
        _addButton = new JButton(_resource.getString("groupMember", "addButton"));
        _addButton.setToolTipText(_resource.getString("dynamicGroupMember", "add_tt"));
        _addButton.addActionListener(this);
        _editButton = new JButton(_resource.getString("groupMember", "editButton"));
        _editButton.setToolTipText(_resource.getString("dynamicGroupMember", "edit_tt"));
        _editButton.addActionListener(this);
        _removeButton =
                new JButton(_resource.getString("groupMember", "removeButton"));
        _removeButton.setToolTipText(_resource.getString("dynamicGroupMember", "remove_tt"));
        _removeButton.addActionListener(this);

        JButtonFactory.resizeGroup(/*_queryButton,*/_addButton,
                _editButton, _removeButton);

        Box buttonBox = new Box(BoxLayout.X_AXIS);
        buttonBox.add(Box.createHorizontalGlue());
        //buttonBox.add(_queryButton);
        //buttonBox.add(Box.createHorizontalStrut(SuiLookAndFeel.COMPONENT_SPACE));
        buttonBox.add(_addButton);
        buttonBox.add(
                Box.createHorizontalStrut(SuiLookAndFeel.COMPONENT_SPACE));
        buttonBox.add(_editButton);
        buttonBox.add( Box.createHorizontalStrut(
                SuiLookAndFeel.SEPARATED_COMPONENT_SPACE));
        buttonBox.add(_removeButton);

        setLayout(new GridBagLayout());
        GridBagUtil.constrain(this, label, 0, 0, 1, 1, 1.0, 0.0,
                GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.VERT_WINDOW_INSET,
                SuiLookAndFeel.HORIZ_WINDOW_INSET, 0,
                SuiLookAndFeel.HORIZ_WINDOW_INSET);
        GridBagUtil.constrain(this, scrollPane, 0, 1, 1, 1, 1.0, 1.0,
                GridBagConstraints.WEST, GridBagConstraints.BOTH, 0,
                SuiLookAndFeel.HORIZ_WINDOW_INSET, 0,
                SuiLookAndFeel.HORIZ_WINDOW_INSET);
        GridBagUtil.constrain(this, buttonBox, 0, 2, 1, 1, 0.0, 0.0,
                GridBagConstraints.EAST, GridBagConstraints.NONE,
                SuiLookAndFeel.SEPARATED_COMPONENT_SPACE,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.VERT_WINDOW_INSET,
                SuiLookAndFeel.HORIZ_WINDOW_INSET);
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
        _resourceEditor = parent;
        _observable = observable;
        _vList = observable.get(ATTR_MEMBER_URL);
        _vOldList = observable.get(ATTR_MEMBER_URL);
        _list.setListData(_vList);
        _list.repaint();
    }

    /**
     * Implements the Observer interface. Updates the fields when notified.
     *
     * @param o    the observable object
     * @param arg  the attribute to update
     */
    public void update(Observable o, Object arg) {
        if ((o instanceof ResourcePageObservable) == false) {
            return;
        }
        ResourcePageObservable observable = (ResourcePageObservable) o;
        if (arg instanceof String) {
            String argString = (String) arg;
            if (argString.equalsIgnoreCase(ATTR_MEMBER_URL)) {
                _vList = observable.get(ATTR_MEMBER_URL);
                _list.setListData(_vList);
                _list.repaint();
            }
        }
    }

    /**
     * Implements the ActionListener interface.
     *
     * @param e  the action event
     */
    public void actionPerformed(ActionEvent e) {
        if (e.getSource().equals(_queryButton)) {
        } else if (e.getSource().equals(_addButton)) {
            String defaultQuery =
                    ("ldap://" + _consoleInfo.getUserHost() + ":" + _consoleInfo.getUserPort() +
                     "/" + _consoleInfo.getUserBaseDN() + "??sub?");
            DynamicQueryDlg dlg =
                    new DynamicQueryDlg(_consoleInfo, null, true,
                    defaultQuery);
            dlg.show();
            if (dlg.isCancel()) {
                return;
            }
            String sResult = dlg.getResult();
            if (sResult != "") {
                _vList.addElement(sResult);
                _list.setListData(_vList);
                _list.repaint();
                if (_observable != null)
                    _observable.replace(ATTR_MEMBER_URL, _vList);
            }
        } else if (e.getSource().equals(_editButton)) {
            String sSelection = (String)_list.getSelectedValue();
            if (sSelection != null) {
                DynamicQueryDlg dlg =
                        new DynamicQueryDlg(_consoleInfo, null/*_consoleInfo.getFrame()*/,
                        true, sSelection);
                //ModalDialogUtil.setDialogLocation(dlg, null);
                dlg.show();
                if (dlg.isCancel()) {
                    return;
                }
                String sResult = dlg.getResult();
                if (sResult != "") {
                    int index = _vList.indexOf(sSelection);
                    if (index != -1) {
                        _vList.insertElementAt(sResult, index);
                        _vList.removeElement(sSelection);
                        _list.setListData(_vList);
                        _list.repaint();
                        if (_observable != null)
                            _observable.replace(ATTR_MEMBER_URL, _vList);
                    }
                }
            }
        } else if (e.getSource().equals(_removeButton)) {
            String sSelection = (String)_list.getSelectedValue();
            if (sSelection != null) {
                _vList.removeElement(sSelection);
                _list.setListData(_vList);
                _list.repaint();
                if (_vList.size() == 0) {
                    if (_observable != null)
                        _observable.delete(ATTR_MEMBER_URL);
                } else {
                    if (_observable != null)
                        _observable.replace(ATTR_MEMBER_URL, _vList);
                }
            }
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
        boolean fReturn = true;

        boolean fSame = true;
        if (_vList.size() == _vOldList.size()) {
            Enumeration eOldList = _vOldList.elements();
            while (eOldList.hasMoreElements()) {
                String sOldValue = (String) eOldList.nextElement();
                boolean fFound = false;
                Enumeration eNewList = _vList.elements();
                while (eNewList.hasMoreElements()) {
                    String sNewValue = (String) eNewList.nextElement();
                    if (sNewValue.equals(sOldValue)) {
                        fFound = true;
                        break;
                    }
                }
                if (!fFound) {
                    fSame = false;
                    break;
                }
            }
        } else {
            fSame = false;
        }
        if (!fSame) {
            Vector vObjectClass = observable.get("objectclass");
            if (vObjectClass.indexOf("groupofurls") == -1) {
                vObjectClass.addElement("groupofurls");
                observable.replace("objectclass",vObjectClass);
            }

            if (_vList.size() == 0) {
                observable.delete(ATTR_MEMBER_URL);
            } else {
                observable.replace(ATTR_MEMBER_URL, _vList);
            }
        }
        return fReturn;
    }

    /**
     * Implements the IResourceEditorPage interface.
      * Clears all information on the page.
     */
    public void clear() {}

    /**
     * Implements the IResourceEditorPage interface.
      * Resets information on the page.
     */
    public void reset() {
    }

    /**
     * Implements the IResourceEditorPage interface.
      * Sets default information on the page.
     */
    public void setDefault() {}

    /**
     * Implements the IResourceEditorPage interface.
      * Specifies whether any information on the page has been modified.
      *
      * @return  true if some information has been modified; false otherwise
     */
    public boolean isModified() {
        return _isModified;
    }

    /**
     * Implements the IResourceEditorPage interface.
      * Sets the modified flag for the page.
      *
      * @param value  true or false
     */
    public void setModified(boolean value) {
        _isModified = value;
    }

    /**
     * Implements the IResourceEditorPage interface.
      * Specifies whether the information on the page is read only.
      *
      * @return  true if some information has been modified; false otherwise
     */
    public boolean isReadOnly() {
        return _isReadOnly;
    }

    /**
     * Implements the IResourceEditorPage interface.
      * Sets the read only flag for the page.
      *
      * @param value  true or false
     */
    public void setReadOnly(boolean value) {
        _isReadOnly = value;
    }

    /**
     * Implements the IResourceEditorPage interface.
      * Sets the enabled flag for the page.
      *
      * @param value  true or false
     */
    public void setEnable(boolean value) {
        _isEnable = value;
    }

    /**
     * Implements the IResourceEditorPage interface.
      * Specifies whether all required information has been provided for
      * the page.
      *
      * @return  true if all required information has been provided; false otherwise
     */
    public boolean isComplete() {
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
     * Implements the IResourceEditorPage interface.
      * Displays help information for the page
     */
    public void help() {
        Help help = new Help(_resource);

        help.contextHelp("ug","ResEditorDynamicGpMembers");
    }
}
