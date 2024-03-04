/** BEGIN COPYRIGHT BLOCK
 * Copyright (C) 2001 Sun Microsystems, Inc.  Used by permission.
 * Copyright (C) 2010 Red Hat, Inc.
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

import java.awt.*;
import java.util.*;
import java.awt.event.*;

import com.netscape.management.client.console.ConsoleInfo;
import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;

import netscape.ldap.*;

import javax.swing.*;


/**
 * ResEditorPosixGpMembers is a plugin for the ResourceEditor. It is used
 * when editing group membership information. This page lets administrators
 * define the group membership statically, assigning specific users to the
 * group.
 *
 * @see IResourceEditorPage
 * @see ResourceEditor
 * @see ResEditorGroupMembers
 */
public class ResEditorPosixGpMembers extends JPanel implements IResourceEditorPage,
Observer, ActionListener, IRPCallBack {

    static final String ATTR_MEMBER_UID = "memberuid";
    static final String ATTR_UID = "uid";

    PickerEditorResourceSet _resource = new PickerEditorResourceSet();
    private String ID;

    VLDirectoryTable _groupMembers;

    boolean _isModified = false;
    boolean _isReadOnly = false;
    boolean _isEnable = true;

    JButton _addUser, _removeUser;

    ConsoleInfo _consoleInfo;
    JFrame _parent;

    Vector delMembers = new Vector();
    Vector addMembers = new Vector();

    ResourcePageObservable _observable;


    /**
    * Constructor
    *
    * @param info    session information
    * @param parent  parent frame
    */
    public ResEditorPosixGpMembers(ConsoleInfo info, JFrame parent) {

        super(true);

        _consoleInfo = info;
        _parent = parent;

        ID = _resource.getString("PosixGroupMember", "ID");

        Hashtable map = new Hashtable();
        String cn = "cn"; // Default values in case info is unavailable
        String cnLabel = "Member Name";
        String uid = "uid";
        String uidLabel = "Member User ID";
        String cnColumnInfo =
                _resource.getString("staticGroupMember", "cnColumnInfo");
        String uidColumnInfo =
                _resource.getString("staticGroupMember", "uidColumnInfo");
        int index = cnColumnInfo.indexOf(',');
        if (index != -1) {
            cn = cnColumnInfo.substring(0, index);
            cnLabel = cnColumnInfo.substring(index + 1);
        }
        index = uidColumnInfo.indexOf(',');
        if (uidColumnInfo.indexOf(',') != -1) {
            uid = uidColumnInfo.substring(0, index);
            uidLabel = uidColumnInfo.substring(index + 1);
        }
        map.put(cn, cnLabel);
        map.put(uid, uidLabel);

        Vector header = new Vector();
        header.addElement(cn);
        header.addElement(uid);

        _groupMembers = new VLDirectoryTable(map, header);
        _groupMembers.setConsoleInfo(info);
        _groupMembers.setTableColumnWidth(0, 100);

        _addUser = new JButton(_resource.getString("groupMember", "addButton"));
        _addUser.setToolTipText(_resource.getString("staticGroupMember", "add_tt"));
        _addUser.addActionListener(this);
        _removeUser = new JButton(_resource.getString("groupMember", "removeButton"));
        _removeUser.setToolTipText(_resource.getString("staticGroupMember", "remove_tt"));
        _removeUser.addActionListener(this);
        JButtonFactory.resizeGroup(_addUser, _removeUser);

        Box buttonBox = new Box(BoxLayout.X_AXIS);
        buttonBox.add(Box.createHorizontalGlue());
        buttonBox.add(_addUser);
        buttonBox.add( Box.createHorizontalStrut(
                SuiLookAndFeel.SEPARATED_COMPONENT_SPACE));
        buttonBox.add(_removeUser);

        setLayout(new GridBagLayout());
        GridBagUtil.constrain(this, _groupMembers, 0, 0, 1, 1, 1.0,
                1.0, GridBagConstraints.WEST, GridBagConstraints.BOTH,
                SuiLookAndFeel.VERT_WINDOW_INSET,
                SuiLookAndFeel.HORIZ_WINDOW_INSET, 0,
                SuiLookAndFeel.HORIZ_WINDOW_INSET);
        GridBagUtil.constrain(this, buttonBox, 0, 1, 1, 1, 0.0, 0.0,
                GridBagConstraints.EAST, GridBagConstraints.NONE,
                SuiLookAndFeel.SEPARATED_COMPONENT_SPACE,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.VERT_WINDOW_INSET,
                SuiLookAndFeel.HORIZ_WINDOW_INSET);
    }

    void browseUidList(Vector uidList) {
        LDAPConnection ldc = _consoleInfo.getUserLDAPConnection();
        for (int i=0; i < uidList.size(); i++) {
            String uid = (String)uidList.elementAt(i);
            _groupMembers.doSearch(ldc,_consoleInfo.getUserBaseDN(),LDAPConnection.SCOPE_SUB,"uid="+uid);
           
        }
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
        Vector members = observable.get(ATTR_MEMBER_UID);
        if (members != null && members.size() > 0) {
           browseUidList(members);
        }
    }


    /**
     * Implements the Observer interface. Updates the fields when notified.
     *
     * @param o    the observable object
     * @param arg  the attribute to update
     */
    public void update(Observable o, Object arg) {
    }


    /**
     * Implements the IRPCallBack interface. Adds the results
     * to the table.
     *
     * @param vResult  Vector of LDAPEntry objects
     */
    public void getResults(Vector vResult) {
        Debug.println("ResEditorPosixGroup.getResults: vResult = " + vResult);

        for (int i = 0; i < vResult.size(); i++) {
            LDAPEntry entry = (LDAPEntry)(vResult.elementAt(i));
            try {
                String uid = entry.getAttribute(ATTR_UID).getStringValues().nextElement().toString();
                // Check if dn was deleted in this session
                boolean previouslyDeleted = delMembers.removeElement(uid);
                if (!previouslyDeleted) {
                    addMembers.addElement(uid);
                }
                _groupMembers.addRow(entry);
            }catch (NullPointerException ex){
                    Debug.println("ResEditorPosixGpMemebers:getResults: uid not found: "+entry);
            }
        }
    }


    /**
     * Implements the ActionListener interface.
     *
     * @param e  the action event
     */
    public void actionPerformed(ActionEvent e) {
        if (e.getSource().equals(_addUser)) {
            ResourcePickerDlg pickerDlg =
                    new ResourcePickerDlg(_consoleInfo, this, _parent);
            pickerDlg.show();
            pickerDlg.dispose();
        } else if (e.getSource().equals(_removeUser)) {
            int selections[] = _groupMembers.getSelectedRows();
            for (int i = 0; i < selections.length; i++) {
                LDAPEntry entry = _groupMembers.getRow(selections[i]);
                try {
                    String uid = entry.getAttribute(ATTR_UID).getStringValues().nextElement().toString();
                // Check if uid was added in this session
                    boolean previouslyAdded = addMembers.removeElement(uid);
                    if (!previouslyAdded) {
                        delMembers.addElement(uid);
                    }                
                }catch (NullPointerException ex){
                        Debug.println("ResEditorPosixGpMemebers:actionPerformed: uid not found: "+entry);
                }
            }
            _groupMembers.deleteRows(selections);
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

        String _POSIXOBJECTCLASS = "posixgroup";
        boolean isNewGroup = observable.isNewUser();// attrReplace == objectclass
        int count = _groupMembers.getRowCount();
        int modSize = delMembers.size() + addMembers.size();

        Debug.println("ResEditorPosixGpMembers.save: observable =" + observable);
        Debug.println("ResEditorPosixGpMembers.save: num mods = " + modSize);
        if (modSize == 0) {
            return true; // nothing to save
        }

        boolean oc_present = false;
        try {
            LDAPEntry entry = observable.getLDAPEntry(observable.getDN(), isNewGroup);
            Enumeration attrVals = entry.getAttribute("objectclass").getStringValues();
            while (attrVals.hasMoreElements()){
                    if (attrVals.nextElement().toString().equalsIgnoreCase(_POSIXOBJECTCLASS)){
                        oc_present = true;
                    }
            }
        } catch (NullPointerException ex) {
            Debug.println("ResEditorPosixGpMembers.save: no entry: "+observable.getDN());
        }
        /**
         * If (count < modSize), then it is more efficient to replace the
         * whole members than to add/delete individual members.
         */
        if (isNewGroup || (count < modSize) || !oc_present) {
            
            if (count > 0) {
                Vector vNewList = new Vector();
                for (int i = 0; i < count; i++) {
                    LDAPEntry ldapEntry = (LDAPEntry)_groupMembers.getRow(i);
                    Debug.println("ResEditorPosixGpMembers.save: entry "+i+": "+ldapEntry);
                    vNewList.addElement(ldapEntry.getAttribute(ATTR_UID).getStringValues().nextElement());
                }
                observable.replace(ATTR_MEMBER_UID, vNewList);
            }
            else {
                observable.delete(ATTR_MEMBER_UID);
            }
        }

        else {
            /**
             * For updates, do not use a very inefficient observable to 
             * replace() the whole 'memberUid' attribute as it can be
             * huge. Instead use own update logic to update only deltas.
             */
            LDAPModificationSet mod = new LDAPModificationSet();
            if (addMembers.size() > 0) {
                LDAPAttribute addAttr  = new LDAPAttribute(ATTR_MEMBER_UID);
                for (int i=0; i< addMembers.size(); i++) {
                    String member = (String) addMembers.elementAt(i);
                    addAttr.addValue(member);
                }
                mod.add(LDAPModification.ADD, addAttr);
            }
            if (delMembers.size() > 0) {
                LDAPAttribute delAttr  = new LDAPAttribute(ATTR_MEMBER_UID);
                for (int i=0; i< delMembers.size(); i++) {
                    String member = (String) delMembers.elementAt(i);
                    delAttr.addValue(member);
                }
                mod.add(LDAPModification.DELETE, delAttr);
            }
            
            LDAPConnection ldc = _consoleInfo.getUserLDAPConnection();
            try {
                if (Debug.isEnabled()) {                    
                    Debug.println("ResEditorPosixGpMembers.save: mod =" + mod);
                }
                ldc.modify(observable.getDN(), mod);
            }
            catch (LDAPException e) {
                Debug.println("ResEditorPosixGpMembers.save : "  + e);
                throw e;
            }
        }

        delMembers.removeAllElements();
        addMembers.removeAllElements();

        return true;
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
    }
}
