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
import com.netscape.management.client.console.*;
import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;


/**
 * ResEditorGroupInfo is a plugin for the ResourceEditor. It is used
 * when editing group information. This page lets administrators define
 * the group name and description.
 *
 * @see IResourceEditorPage
 * @see ResourceEditor
 */
public class ResEditorGroupInfo extends JPanel implements IResourceEditorPage,
Observer {
    PickerEditorResourceSet _resource = new PickerEditorResourceSet();
    private String ID;

    JTextField _groupName;
    JTextArea _groupDescription;

    String _oldGroupName;

    boolean _isModified = false;
    boolean _isReadOnly = false;
    boolean _isEnable = true;

    ResourceEditor _resourceEditor;

    ConsoleInfo _info;
    String _sIndex;
    String _sDesc;

    ResourcePageObservable _observable;

    /**
     * Used to notify the ResourcePageObservable when a value has changed.
     * Note that this updates all observers.
     */
    FocusAdapter _focusAdaptor = new FocusAdapter() {
                public void focusLost(FocusEvent e) {

                    // 550649 Chinese locale: If a focus is lost because the
                    // window is no more active, do not update observable. Do it
                    // only when another components in the same window gets focus.
                    Window w = (Window) SwingUtilities.getAncestorOfClass(Window.class,
                                        ResEditorGroupInfo.this);
                    if(w != null && w.getFocusOwner() == null) {
                        return;
                    }
 
                    if (_observable == null) {
                        return;
                    }
                    Component src = e.getComponent();
                    if (src == _groupName) {
                        _observable.replace(_sIndex, _groupName.getText());
                    } else if (src == _groupDescription) {
                        Vector vTmp = new Vector();
                        StringTokenizer st = new StringTokenizer(
                                _groupDescription.getText(), "\n\r");
                        while (st.hasMoreTokens()) {
                            vTmp.addElement(st.nextElement());
                        }
                        _observable.replace(_sDesc, vTmp);
                    }
                }
            };


    /**
    * Constructor
    */
    public ResEditorGroupInfo() {
        super(true);
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
        ID = _resource.getString("groupInfoPage", "ID");
        _resourceEditor = parent;
        _observable = observable;
        _info = observable.getConsoleInfo();
        _sIndex = ResourceEditor.getGroupRDNComponent();
        _sDesc = "description";

        JLabel infoLabel = new JLabel(_resource.getString("userPage","required"));
        JLabel nameLabel = new JLabel(
                _resource.getString("groupInfoPage", "name"),
                SwingConstants.RIGHT);
        JLabel descriptionLabel = new JLabel(
                _resource.getString("groupInfoPage", "description"),
                SwingConstants.RIGHT);
        JLabel blankLabel = new JLabel(""); // Prevents components of this panel from centering

        _groupName = new JTextField();
        nameLabel.setLabelFor(_groupName);
        _groupDescription = new UGTextArea();
        descriptionLabel.setLabelFor(_groupDescription);

        _groupName.addFocusListener(_focusAdaptor);
        _groupDescription.addFocusListener(_focusAdaptor);

        JPanel p = new JPanel(new GridBagLayout());
        GridBagUtil.constrain(p, nameLabel, 0, 0, 1, 1, 0.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.VERT_WINDOW_INSET,
                SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);
        GridBagUtil.constrain(p, _groupName, 1, 0,
                GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.VERT_WINDOW_INSET,
                SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0,
                SuiLookAndFeel.HORIZ_WINDOW_INSET);

        GridBagUtil.constrain(p, descriptionLabel, 0, 1, 1, 1, 0.0,
                0.0, GridBagConstraints.NORTHWEST,
                GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);
        GridBagUtil.constrain(p, _groupDescription, 1, 1,
                GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.BOTH,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0,
                SuiLookAndFeel.HORIZ_WINDOW_INSET);

        GridBagUtil.constrain(p, infoLabel, 1, 2,
                GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.VERT_WINDOW_INSET,
                SuiLookAndFeel.HORIZ_WINDOW_INSET, 0,
                SuiLookAndFeel.HORIZ_WINDOW_INSET);

        GridBagUtil.constrain(p, blankLabel, 0, 3,
                GridBagConstraints.REMAINDER,
                GridBagConstraints.REMAINDER, 1.0, 1.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.BOTH,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.HORIZ_WINDOW_INSET,
                SuiLookAndFeel.VERT_WINDOW_INSET,
                SuiLookAndFeel.HORIZ_WINDOW_INSET);

        JScrollPane sp = new JScrollPane(p);
        sp.setBorder(null);

        setLayout(new BorderLayout());
        add("Center", sp);

        _oldGroupName = observable.get(_sIndex, 0);
        _groupName.setText(_oldGroupName);

        Vector vDesc = observable.get(_sDesc);
        Enumeration eDesc = vDesc.elements();
        if (eDesc.hasMoreElements()) {
            _groupDescription.append((String) eDesc.nextElement());
        }
        while (eDesc.hasMoreElements()) {
            _groupDescription.append("\n" + eDesc.nextElement());
        }
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
            if (argString.equalsIgnoreCase(_sIndex)) {
                _groupName.setText(observable.get(_sIndex, 0));
            } else if (argString.equalsIgnoreCase(_sDesc)) {
                _groupDescription.setText("");
                Vector vDesc = observable.get(_sDesc);
                Enumeration eDesc = vDesc.elements();
                if (eDesc.hasMoreElements()) {
                    _groupDescription.append((String) eDesc.nextElement());
                }
                while (eDesc.hasMoreElements()) {
                    _groupDescription.append("\n" + eDesc.nextElement());
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
        if (_groupName.getText().equals(_oldGroupName) == false) {
            if (_groupName.getText().trim().length() == 0) {
                observable.delete(_sIndex, _oldGroupName);
                _oldGroupName = "";
            } else {
                String newGroupName = _groupName.getText().trim();
                observable.replace(_sIndex, newGroupName);
                _oldGroupName = newGroupName;
            }
        }

        Vector vTmp = new Vector();
        StringTokenizer st =
                new StringTokenizer(_groupDescription.getText(), "\n\r");
        while (st.hasMoreTokens()) {
            vTmp.addElement(st.nextElement());
        }
        if (vTmp.size() == 0) {
            observable.delete(_sDesc);
        } else {
            observable.replace(_sDesc, vTmp);
        }
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
        _groupName.setText("");
        _groupDescription.setText("");
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
        if (_groupName.getText().trim().length() == 0) {
            SuiOptionPane.showMessageDialog(null,
                    _resource.getString("resourceEditor", "IncompleteText"),
                    _resource.getString("resourceEditor",
                    "IncompleteTitle"), SuiOptionPane.ERROR_MESSAGE);
            ModalDialogUtil.sleep();
            return false;
        }
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

        help.contextHelp("ug","ResEditorGroupInfoDef");
    }
}
