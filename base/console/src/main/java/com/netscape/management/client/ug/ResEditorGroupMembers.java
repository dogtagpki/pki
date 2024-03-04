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
import javax.swing.*;
import com.netscape.management.nmclf.*;
import com.netscape.management.client.util.*;

/**
 * ResEditorGroupMembers is a plugin for the ResourceEditor. It is used
 * when editing group membership information. It serves to group the
 * three ways of specifying group membership: static, dynamic, and
 * certificate.
 *
 * @see IResourceEditorPage
 * @see ResourceEditor
 * @see ResEditorStaticGpMembers
 * @see ResEditorDynamicGpMembers
 * @see ResEditorCertGroupMembers
 */
public class ResEditorGroupMembers extends JPanel implements IResourceEditorPage,
Observer {

    PickerEditorResourceSet _resource = new PickerEditorResourceSet();
    private String ID;

    ResourceEditor _resourceEditor;

    ResEditorStaticGpMembers staticGroup;
    ResEditorDynamicGpMembers dynamicGroup;
    ResEditorCertGroupMembers certGroup;

    JTabbedPane _tabPane;

    private int ACTIVE_PANE = 0;

    /**
    * Constructor
    */
    public ResEditorGroupMembers() {

        super(new GridBagLayout(), false);

        _tabPane = new JTabbedPane();
        GridBagUtil.constrain(this, _tabPane, 0, 0,
                GridBagConstraints.REMAINDER,
                GridBagConstraints.REMAINDER, 1.0, 1.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.BOTH,
                SuiLookAndFeel.SEPARATED_COMPONENT_SPACE,
                SuiLookAndFeel.SEPARATED_COMPONENT_SPACE,
                SuiLookAndFeel.SEPARATED_COMPONENT_SPACE,
                SuiLookAndFeel.SEPARATED_COMPONENT_SPACE);
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

        staticGroup = new ResEditorStaticGpMembers(
                _resourceEditor.getConsoleInfo(), parent.getFrame());
        dynamicGroup = new ResEditorDynamicGpMembers(
                _resourceEditor.getConsoleInfo());
        certGroup = new ResEditorCertGroupMembers(
                _resourceEditor.getConsoleInfo());

        ID = _resource.getString("groupMember", "ID");

        staticGroup.initialize(observable, parent);
        dynamicGroup.initialize(observable, parent);
        certGroup.initialize(observable, parent);

        for (int i = _tabPane.getTabCount() - 1; i >= 0; i--) {
            _tabPane.removeTabAt(i);
        }
        _tabPane.addTab(staticGroup.getDisplayName(), staticGroup);
        _tabPane.addTab(dynamicGroup.getDisplayName(), dynamicGroup);
        _tabPane.addTab(certGroup.getDisplayName(), certGroup);
        _tabPane.setSelectedIndex(0);

    }

    /**
     * Implements the Observer interface. Updates the fields when notified.
     *
     * @param o    the observable object
     * @param arg  the attribute to update
     */
    public void update(Observable o, Object arg) {
        staticGroup.update(o, arg);
        dynamicGroup.update(o, arg);
        certGroup.update(o, arg);
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

        fReturn &= staticGroup.save(observable);
        fReturn &= dynamicGroup.save(observable);
        fReturn &= certGroup.save(observable);
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
        boolean fReturn = false;
        fReturn = (staticGroup.isModified() &&
                dynamicGroup.isModified() && certGroup.isModified());
        return fReturn;
    }

    /**
     * Implements the IResourceEditorPage interface.
      * Sets the modified flag for the page.
      *
      * @param value  true or false
     */
    public void setModified(boolean value) {
        staticGroup.setModified(value);
        dynamicGroup.setModified(value);
        certGroup.setModified(value);
    }

    /**
     * Implements the IResourceEditorPage interface.
      * Specifies whether the information on the page is read only.
      *
      * @return  true if some information has been modified; false otherwise
     */
    public boolean isReadOnly() {
        boolean fReturn = false;
        fReturn = (staticGroup.isReadOnly() &&
                dynamicGroup.isReadOnly() && certGroup.isReadOnly());
        return fReturn;
    }

    /**
     * Implements the IResourceEditorPage interface.
      * Sets the read only flag for the page.
      *
      * @param value  true or false
     */
    public void setReadOnly(boolean value) {
        staticGroup.setReadOnly(value);
        dynamicGroup.setReadOnly(value);
        certGroup.setReadOnly(value);
    }

    /**
     * Implements the IResourceEditorPage interface.
      * Sets the enabled flag for the page.
      *
      * @param value  true or false
     */
    public void setEnable(boolean value) {
        staticGroup.setEnable(value);
        dynamicGroup.setEnable(value);
        certGroup.setEnable(value);
    }

    /**
     * Implements the IResourceEditorPage interface.
      * Specifies whether all required information has been provided for
      * the page.
      *
      * @return  true if all required information has been provided; false otherwise
     */
    public boolean isComplete() {
        boolean fReturn = false;
        fReturn = (staticGroup.isComplete() &&
                dynamicGroup.isComplete() && certGroup.isComplete());
        return fReturn;
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
        Component c = _tabPane.getSelectedComponent();
        if (c instanceof IResourceEditorPage) {
            ((IResourceEditorPage) c).help();
        }
    }
}

