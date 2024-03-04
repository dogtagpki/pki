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

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import javax.swing.*;
import com.netscape.management.client.console.*;
import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;


/**
 * ResEditorPasswordPage is a plugin for the ResourceEditor. It is used
 * when editing user password information. This is no longer used because
 * the password information has been folded into ResEditorUserPage.
 *
 * @see IResourceEditorPage
 * @see ResourceEditor
 * @see ResEditorUserPage
 */
public class ResEditorPasswordPage extends JPanel implements IResourceEditorPage,
Observer {
    static final String ATTR_USER_PASSWORD = "userpassword";

    PickerEditorResourceSet _resource = new PickerEditorResourceSet();
    private String ID;

    SuiPasswordField _newPassword, _confirmPassword;

    String _password;

    boolean _isModified = false;
    boolean _isReadOnly = false;
    boolean _isEnable = true;

    boolean _passwordChange;
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
                    Window w = (Window) SwingUtilities.getAncestorOfClass(Window.class, ResEditorPasswordPage.this);
                    if(w != null && w.getFocusOwner() == null) {
                        return;
                    }
 
                    if (_observable == null) {
                        return;
                    }
                    Component src = e.getComponent();
                    if (src == _confirmPassword &&
                            _confirmPassword.getText().equals(
                            _newPassword.getText())) {
                        _observable.replace(ATTR_USER_PASSWORD,
                                _confirmPassword.getText());
                    }
                }
            };


    /**
    * Constructor
    */
    public ResEditorPasswordPage() {
        super();

        ID = _resource.getString("passwordPage", "ID");

        JLabel passwordLabel = new JLabel(
                _resource.getString("passwordPage", "newPasswd"),
                SwingConstants.RIGHT);
        JLabel confirmPasswordLabel = new JLabel(
                _resource.getString("passwordPage", "confirmPasswd"),
                SwingConstants.RIGHT);
        JLabel blankLabel = new JLabel(""); // Prevents components of this panel from centering

        _newPassword = new SuiPasswordField("");
        passwordLabel.setLabelFor(_newPassword);
        _confirmPassword = new SuiPasswordField("");
        confirmPasswordLabel.setLabelFor(_confirmPassword);
        _confirmPassword.addFocusListener(_focusAdaptor); // Only want to update when new == confirm

        setLayout(new GridBagLayout());
        GridBagUtil.constrain(this, passwordLabel, 0, 0, 1, 1, 0.0,
                0.0, GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.VERT_WINDOW_INSET,
                SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);
        GridBagUtil.constrain(this, _newPassword, 1, 0,
                GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.VERT_WINDOW_INSET,
                SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0,
                SuiLookAndFeel.HORIZ_WINDOW_INSET);

        GridBagUtil.constrain(this, confirmPasswordLabel, 0, 1, 1, 1,
                0.0, 0.0, GridBagConstraints.WEST,
                GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);
        GridBagUtil.constrain(this, _confirmPassword, 1, 1,
                GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0,
                SuiLookAndFeel.HORIZ_WINDOW_INSET);

        GridBagUtil.constrain(this, blankLabel, 0, 2,
                GridBagConstraints.REMAINDER,
                GridBagConstraints.REMAINDER, 1.0, 1.0,
                GridBagConstraints.WEST, GridBagConstraints.BOTH,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.HORIZ_WINDOW_INSET,
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
        _observable = observable;
        _password = observable.get(ATTR_USER_PASSWORD, 0);
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
            if (argString.equalsIgnoreCase(ATTR_USER_PASSWORD)) {
                _newPassword.setText(
                        observable.get(ATTR_USER_PASSWORD, 0));
                _confirmPassword.setText(
                        observable.get(ATTR_USER_PASSWORD, 0));
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

        if (_passwordChange) {
            observable.replace(ATTR_USER_PASSWORD,
                    _confirmPassword.getText());
        }
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
        _newPassword.setText("");
        _confirmPassword.setText("");
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
        boolean fcomplete = true;
        ConsoleInfo info = _observable.getConsoleInfo();

        //needed SHA encription package,
        if ((_confirmPassword.getText().length() > 0) ||
                (_newPassword.getText().length() > 0)) {
            if (_newPassword.getText().equals(_confirmPassword.getText())) {
                _passwordChange = true;
                fcomplete = true;
            } else {
                SuiOptionPane.showMessageDialog(info.getFrame(),
                        _resource.getString("passwordPage",
                        "newpasswordmismatch-text"),
                        _resource.getString("passwordPage",
                        "newpasswordmismatch-title"),
                        SuiOptionPane.ERROR_MESSAGE);
                ModalDialogUtil.sleep();
                fcomplete = false;
            }
        }

        return fcomplete;
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

        help.contextHelp("ug","ResEditorPasswordPage");
    }
}
