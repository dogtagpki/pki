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

import com.netscape.management.client.console.ConsoleInfo;
import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;

import netscape.ldap.util.DN;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.text.*;


/**
 * ResEditorUserPage is a plugin for the ResourceEditor. It is used
 * when editing user information. This lets administrators specify the
 * person's name, email address, password, etc.
 *
 * @see IResourceEditorPage
 * @see ResourceEditor
 */
public class ResEditorUserPage extends JPanel implements IResourceEditorPage,
Observer, DocumentListener {

    static final String ID_FORMAT_MAIL = "mail";
    static final String ID_FORMAT_NTUSER = "ntuser";
    static final String ID_FORMAT_FIRSTLETTER_LASTNAME = "firstletter_lastname";
    static final String ID_FORMAT_GIVENNAME_FIRSTLETTER = "givenname_firstletter";
    static final String ID_FORMAT_LASTNAME_GIVENNAME = "lastname_givenname";
    static final String ID_FORMAT_GIVENNAME_LASTNAME = "givenname_lastname";

    private String ID;

    JTextField _firstName;
    JTextField _lastName;
    JTextArea _fullName;
    JTextField _userID;
    JTextArea _email;
    JTextArea _phone;
    JTextArea _fax;
    SuiPasswordField _newPassword;
    SuiPasswordField _confirmPassword;

    ConsoleInfo _info;

    String _sSystemUID = null;

    static final String USER_PAGE = "userPage";
    static final String ATTR_FIRST_NAME = "givenname";
    static final String ATTR_LAST_NAME = "sn";
    static final String ATTR_FULL_NAME = "cn";
    static final String ATTR_USER_ID = "uid";
    static final String ATTR_MAIL = "mail";
    static final String ATTR_PHONE = "telephonenumber";
    static final String ATTR_FAX = "facsimiletelephonenumber";
    static final String ATTR_USER_PASSWORD = "userpassword";

    static final String ADMIN_BASE_DN =
       "ou=Administrators, ou=TopologyManagement, o=netscapeRoot";

    String _oldFirstName;
    String _oldLastName;
    String _oldUserID;
    String _oldPassword;

    boolean _isModified = false;
    boolean _isReadOnly = false;
    boolean _isEnable = true;
    boolean _isAdmin = false;

    boolean _createNewUser;

    boolean _fFillFullName;
    boolean _fUpdateUID;
    int _iFullnameFormat;
    Document _fullNameDoc;
    Document _userIDDoc;
    ResourcePageObservable _observable;

    PickerEditorResourceSet _resource = new PickerEditorResourceSet();

    /**
     * Used to notify the ResourcePageObservable when a value has changed.
     * Note that this updates all observers.
     */
    FocusAdapter _focusAdaptor = new FocusAdapter() {
                public void focusLost(FocusEvent e) {

                    // 550649 Chinese locale: If a focus is lost because the
                    // window is no more active, do not update observable. Do it
                    // only when another components in the same window gets focus.
                    Window w = (Window) SwingUtilities.getAncestorOfClass(Window.class, ResEditorUserPage.this);
                    if(w != null && w.getFocusOwner() == null) {
                        return;
                    }

                    Vector vTmp = new Vector();
                    if (_observable == null) {
                        return;
                    }
                    Component src = e.getComponent();
                    if (src == _firstName) {
                        // Changes to first and last names result in changes to the
                        // full name and user ID.
                        _observable.replace(ATTR_FIRST_NAME,
                                _firstName.getText());
                        _observable.replace(ATTR_USER_ID,
                                _userID.getText());
                        vTmp.removeAllElements();
                        StringTokenizer st = new StringTokenizer(
                                _fullName.getText(), "\n\r");
                        while (st.hasMoreTokens()) {
                            vTmp.addElement(st.nextElement());
                        }
                        _observable.replace(ATTR_FULL_NAME, vTmp);
                    } else if (src == _lastName) {
                        _observable.replace(ATTR_LAST_NAME,
                                _lastName.getText());
                        _observable.replace(ATTR_USER_ID,
                                _userID.getText());
                        vTmp.removeAllElements();
                        StringTokenizer st = new StringTokenizer(
                                _fullName.getText(), "\n\r");
                        while (st.hasMoreTokens()) {
                            vTmp.addElement(st.nextElement());
                        }
                        _observable.replace(ATTR_FULL_NAME, vTmp);
                    } else if (src == _fullName) {
                        vTmp.removeAllElements();
                        StringTokenizer st = new StringTokenizer(
                                _fullName.getText(), "\n\r");
                        while (st.hasMoreTokens()) {
                            vTmp.addElement(st.nextElement());
                        }
                        _observable.replace(ATTR_FULL_NAME, vTmp);
                    } else if (src == _userID) {
                        _observable.replace(ATTR_USER_ID,
                                _userID.getText());
                    } else if (src == _confirmPassword &&
                            _confirmPassword.getText().equals(
                            _newPassword.getText())) {
                        _observable.replace(ATTR_USER_PASSWORD,
                                _confirmPassword.getText());
                    } else if (src == _email) {
                        vTmp.removeAllElements();
                        StringTokenizer st =
                                new StringTokenizer(_email.getText(),
                                "\n\r");
                        while (st.hasMoreTokens()) {
                            vTmp.addElement(st.nextElement());
                        }
                        _observable.replace(ATTR_MAIL, vTmp);
                    } else if (src == _phone) {
                        vTmp.removeAllElements();
                        StringTokenizer st =
                                new StringTokenizer(_phone.getText(),
                                "\n\r");
                        while (st.hasMoreTokens()) {
                            vTmp.addElement(st.nextElement());
                        }
                        _observable.replace(ATTR_PHONE, vTmp);
                    } else if (src == _fax) {
                        vTmp.removeAllElements();
                        StringTokenizer st =
                                new StringTokenizer(_fax.getText(), "\n\r");
                        while (st.hasMoreTokens()) {
                            vTmp.addElement(st.nextElement());
                        }
                        _observable.replace(ATTR_FAX, vTmp);
                    }
                }
            };


    /**
    * Constructor
    */
    public ResEditorUserPage() {
        super(true);
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
            if (_sSystemUID != null) {
                if (_sSystemUID.equals(argString)) {
                    updateUID();
                }
            }
            if (argString.equalsIgnoreCase(ATTR_MAIL)) {
                _email.setText("");
                Vector vEmail = observable.get(ATTR_MAIL);
                Enumeration eEmail = vEmail.elements();
                if (eEmail.hasMoreElements()) {
                    _email.append((String) eEmail.nextElement());
                }
                while (eEmail.hasMoreElements()) {
                    _email.append("\n" + eEmail.nextElement());
                }
                
            } else if (argString.equalsIgnoreCase(ATTR_FIRST_NAME)) {
                _firstName.setText(observable.get(ATTR_FIRST_NAME, 0));
            } else if (argString.equalsIgnoreCase(ATTR_LAST_NAME)) {
                _lastName.setText(observable.get(ATTR_LAST_NAME, 0));
            } else if (argString.equalsIgnoreCase(ATTR_FULL_NAME)) {
                _fullNameDoc.removeDocumentListener(this);
                _fullName.setText("");
                Vector vFullname = observable.get(ATTR_FULL_NAME);
                Enumeration eFullname = vFullname.elements();
                if (eFullname.hasMoreElements()) {
                    _fullName.append((String) eFullname.nextElement());
                }
                while (eFullname.hasMoreElements()) {
                    _fullName.append("\n" + eFullname.nextElement());
                }
                _fullNameDoc.addDocumentListener(this);
            } else if (argString.equalsIgnoreCase(ATTR_USER_ID)) {
                _userIDDoc.removeDocumentListener(this);
                _userID.setText(observable.get(ATTR_USER_ID, 0));
                _userIDDoc.addDocumentListener(this);
            } else if (argString.equalsIgnoreCase(ATTR_USER_PASSWORD)) {
                _newPassword.setText(
                        observable.get(ATTR_USER_PASSWORD, 0));
                _confirmPassword.setText(
                        observable.get(ATTR_USER_PASSWORD, 0));
            } else if (argString.equalsIgnoreCase(ATTR_PHONE)) {
                _phone.setText("");
                Vector vPhone = observable.get(ATTR_PHONE);
                Enumeration ePhone = vPhone.elements();
                if (ePhone.hasMoreElements()) {
                    _phone.append((String) ePhone.nextElement());
                }
                while (ePhone.hasMoreElements()) {
                    _phone.append("\n" + ePhone.nextElement());
                }
            } else if (argString.equalsIgnoreCase(ATTR_FAX)) {
                _fax.setText("");
                Vector vFax = observable.get(ATTR_FAX);
                Enumeration eFax = vFax.elements();
                if (eFax.hasMoreElements()) {
                    _fax.append((String) eFax.nextElement());
                }
                while (eFax.hasMoreElements()) {
                    _fax.append("\n" + eFax.nextElement());
                }
            }
        }
    }




    private void uiSetup(boolean newUser) {
        ID = _resource.getString(USER_PAGE, "ID");

        JLabel infoLabel = new JLabel(_resource.getString(USER_PAGE, "required"));

        JLabel firstNameLabel = null;
        if (newUser) {
            firstNameLabel = new JLabel(
                _resource.getString(USER_PAGE, "firstName"),
                SwingConstants.RIGHT);
        } else {
            firstNameLabel = new JLabel(
                _resource.getString(USER_PAGE, "firstNameNotRequired"),
                SwingConstants.RIGHT);
        }
        JLabel lastNameLabel =
                new JLabel(_resource.getString(USER_PAGE, "lastName"),
                SwingConstants.RIGHT);
        JLabel fullNameLabel =
                new JLabel(_resource.getString(USER_PAGE, "fullName"),
                SwingConstants.RIGHT);
        JLabel userIDLabel =
                new JLabel(_resource.getString(USER_PAGE, "userID"),
                SwingConstants.RIGHT);

        JLabel passwordLabel = null;
        JLabel confirmPasswordLabel = null;
        if (_isAdmin) { // password is a required field
            passwordLabel =
                new JLabel(_resource.getString(USER_PAGE, "passwdRequired"),
                SwingConstants.RIGHT);
            confirmPasswordLabel = new JLabel(
                _resource.getString(USER_PAGE, "confirmPasswdRequired"),
                SwingConstants.RIGHT);
        }
        else {
            passwordLabel =
                new JLabel(_resource.getString(USER_PAGE, "passwd"),
                SwingConstants.RIGHT);
            confirmPasswordLabel = new JLabel(
                _resource.getString(USER_PAGE, "confirmPasswd"),
                SwingConstants.RIGHT);
        }

        JLabel emailLabel =
                new JLabel(_resource.getString(USER_PAGE, "email"),
                SwingConstants.RIGHT);
        JLabel exampleEmailLabel = new JLabel(
                _resource.getString(USER_PAGE, "exampleEmail"),
                SwingConstants.RIGHT);
        JLabel phoneLabel =
                new JLabel(_resource.getString(USER_PAGE, "phone"),
                SwingConstants.RIGHT);
        JLabel faxLabel = new JLabel(_resource.getString(USER_PAGE, "fax"),
                SwingConstants.RIGHT);
        JLabel blankLabel = new JLabel(""); // Prevents components of this panel from centering

        _firstName = new JTextField();
        firstNameLabel.setLabelFor(_firstName);
        _lastName = new JTextField();
        lastNameLabel.setLabelFor(_lastName);
        _fullName = new UGTextArea();
        fullNameLabel.setLabelFor(_fullName);
        _userID = new JTextField();
        userIDLabel.setLabelFor(_userID);
        _newPassword = new SuiPasswordField("");
        passwordLabel.setLabelFor(_newPassword);
        _confirmPassword = new SuiPasswordField("");
        confirmPasswordLabel.setLabelFor(_confirmPassword);
        _email = new UGTextArea();
        emailLabel.setLabelFor(_email);
        _phone = new UGTextArea();
        phoneLabel.setLabelFor(_phone);
        _fax = new UGTextArea();
        faxLabel.setLabelFor(_fax);

        _firstName.addFocusListener(_focusAdaptor);
        _lastName.addFocusListener(_focusAdaptor);
        _fullName.addFocusListener(_focusAdaptor);
        _userID.addFocusListener(_focusAdaptor);
        _confirmPassword.addFocusListener(_focusAdaptor); // Only want to update when new == confirm
        _email.addFocusListener(_focusAdaptor);
        _phone.addFocusListener(_focusAdaptor);
        _fax.addFocusListener(_focusAdaptor);


        // Layout widgets
        JPanel p = new JPanel(new GridBagLayout());
        GridBagUtil.constrain(p, firstNameLabel, 0, 0, 1, 1, 0.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.VERT_WINDOW_INSET,
                SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);
        GridBagUtil.constrain(p, _firstName, 1, 0,
                GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.VERT_WINDOW_INSET,
                SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0,
                SuiLookAndFeel.HORIZ_WINDOW_INSET);

        GridBagUtil.constrain(p, lastNameLabel, 0, 1, 1, 1, 0.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);
        GridBagUtil.constrain(p, _lastName, 1, 1,
                GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0,
                SuiLookAndFeel.HORIZ_WINDOW_INSET);

        GridBagUtil.constrain(p, fullNameLabel, 0, 2, 1, 1, 0.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);
        GridBagUtil.constrain(p, _fullName, 1, 2,
                GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.BOTH,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0,
                SuiLookAndFeel.HORIZ_WINDOW_INSET);

        GridBagUtil.constrain(p, userIDLabel, 0, 3, 1, 1, 0.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);
        GridBagUtil.constrain(p, _userID, 1, 3,
                GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0,
                SuiLookAndFeel.HORIZ_WINDOW_INSET);

        GridBagUtil.constrain(p, passwordLabel, 0, 4, 1, 1, 0.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);
        GridBagUtil.constrain(p, _newPassword, 1, 4,
                GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0,
                SuiLookAndFeel.HORIZ_WINDOW_INSET);

        GridBagUtil.constrain(p, confirmPasswordLabel, 0, 5, 1, 1, 0.0,
                0.0, GridBagConstraints.NORTHWEST,
                GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);
        GridBagUtil.constrain(p, _confirmPassword, 1, 5,
                GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0,
                SuiLookAndFeel.HORIZ_WINDOW_INSET);

        GridBagUtil.constrain(p, emailLabel, 0, 6, 1, 1, 0.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);
        GridBagUtil.constrain(p, _email, 1, 6, 1, 1, 1.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0, 0);
        GridBagUtil.constrain(p, exampleEmailLabel, 2, 6, 1, 1, 0.0,
                0.0, GridBagConstraints.NORTHWEST,
                GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0,
                SuiLookAndFeel.HORIZ_WINDOW_INSET);

        GridBagUtil.constrain(p, phoneLabel, 0, 7, 1, 1, 0.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);
        GridBagUtil.constrain(p, _phone, 1, 7,
                GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.BOTH,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0,
                SuiLookAndFeel.HORIZ_WINDOW_INSET);

        GridBagUtil.constrain(p, faxLabel, 0, 8, 1, 1, 0.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);
        GridBagUtil.constrain(p, _fax, 1, 8,
                GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.BOTH,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0,
                SuiLookAndFeel.HORIZ_WINDOW_INSET);

        GridBagUtil.constrain(p, infoLabel, 1, 9,
                GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.HORIZ_WINDOW_INSET, 0,
                SuiLookAndFeel.HORIZ_WINDOW_INSET);

        GridBagUtil.constrain(p, blankLabel, 0, 10,
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

        _isAdmin = checkAdmin(observable);

        //Try setup ui once only.
        if ((_observable != observable) ||
                (_info != parent.getConsoleInfo())) {
            uiSetup(observable.isNewUser() || (observable.get(ATTR_FIRST_NAME, 0).length() > 0));
        } else {
            //reuse the old gui, just initialize those fields
            _fullName.setText(null);
            _phone.setText(null);
            _fax.setText(null);
            _email.setText(null);            
        }

        _info = parent.getConsoleInfo();
        _observable = observable;
        _createNewUser = observable.isNewUser();

        // Initialize fields
        Vector vFullname = observable.get(ATTR_FULL_NAME);
        Enumeration eFullname = vFullname.elements();
        if (eFullname.hasMoreElements()) {
            _fullName.append((String) eFullname.nextElement());
        }
        while (eFullname.hasMoreElements()) {
            _fullName.append("\n" + eFullname.nextElement());
        }
        _fFillFullName = (vFullname.size() == 0);
        _fullNameDoc = _fullName.getDocument();
        _fullNameDoc.addDocumentListener(this);


        _oldLastName = observable.get(ATTR_LAST_NAME, 0);
        _lastName.setText(_oldLastName);
        Document doc = _lastName.getDocument();
        doc.addDocumentListener(this);

        _oldUserID = observable.get(ATTR_USER_ID, 0);
        _userID.setText(_oldUserID);
        _userIDDoc = _userID.getDocument();
        _userIDDoc.addDocumentListener(this);
        _fUpdateUID = false;
        if ((_oldUserID == null) || (_oldUserID.equals(""))) {
            _fUpdateUID = true;
        }

        _oldPassword = observable.get(ATTR_USER_PASSWORD, 0);
        _newPassword.setText(_oldPassword);
        _confirmPassword.setText(_oldPassword);

        _oldFirstName = observable.get(ATTR_FIRST_NAME, 0);
        _firstName.setText(_oldFirstName);
        doc = _firstName.getDocument();
        doc.addDocumentListener(this);

        Vector vEmail = observable.get(ATTR_MAIL);
        Enumeration eEmail = vEmail.elements();
        if (eEmail.hasMoreElements()) {
            _email.append((String) eEmail.nextElement());
        }
        while (eEmail.hasMoreElements()) {
            _email.append("\n" + eEmail.nextElement());
        }
        
        
        Vector vPhone = observable.get(ATTR_PHONE);
        Enumeration ePhone = vPhone.elements();
        if (ePhone.hasMoreElements()) {
            _phone.append((String) ePhone.nextElement());
        }
        while (ePhone.hasMoreElements()) {
            _phone.append("\n" + ePhone.nextElement());
        }

        Vector vFax = observable.get(ATTR_FAX);
        Enumeration eFax = vFax.elements();
        if (eFax.hasMoreElements()) {
            _fax.append((String) eFax.nextElement());
        }
        while (eFax.hasMoreElements()) {
            _fax.append("\n" + eFax.nextElement());
        }

        _sSystemUID = ResourceEditor.getUniqueAttribute();
        if ((_sSystemUID != null) && (!_sSystemUID.equals(""))) {
            if (_sSystemUID.equals(ATTR_USER_ID)) {
                // if unique attribute = uid, then do something special
                String sAttribute = ResourceEditor.getUserIDFormat();
                if (sAttribute.toLowerCase().equalsIgnoreCase(
                        ID_FORMAT_NTUSER)) {
                    _sSystemUID = "ntUserDomainID";
                } else if ( sAttribute.toLowerCase().equalsIgnoreCase(
                        ID_FORMAT_MAIL)) {
                    _sSystemUID = ID_FORMAT_MAIL;
                } else if ( sAttribute.toLowerCase().equalsIgnoreCase(
                        ID_FORMAT_FIRSTLETTER_LASTNAME)) {
                    _sSystemUID = ID_FORMAT_FIRSTLETTER_LASTNAME;
                } else if ( sAttribute.toLowerCase().equalsIgnoreCase(
                        ID_FORMAT_GIVENNAME_FIRSTLETTER)) {
                    _sSystemUID = ID_FORMAT_GIVENNAME_FIRSTLETTER;
                } else if ( sAttribute.toLowerCase().equalsIgnoreCase(
                        ID_FORMAT_LASTNAME_GIVENNAME)) {
                    _sSystemUID = ID_FORMAT_LASTNAME_GIVENNAME;
                } else {
                    _sSystemUID = ID_FORMAT_GIVENNAME_LASTNAME;
                }
            }
        }

        //try construct first name from full name
        /*if ((_firstName.getText().length() == 0) &&
            (_fullName.getText().length() != 0)) {
            String tempFullName = null;
            if (_fullName.getText().indexOf("\n") == -1) {
                tempFullName = _fullName.getText();
            } else {
                tempFullName = _fullName.getText().substring(0,
                        _fullName.getText().indexOf("\n"));
            }

            if (tempFullName.indexOf(" ") != -1) {
                _firstName.setText( tempFullName.substring(0,
                        tempFullName.indexOf(" ")));
            } else {
                _firstName.setText(tempFullName);
            }
        }*/
    }

    /**
      * Check if the user is a Configuration Administrator
      *
      * @return  flag whether the user is a Configuration Administrator
      */
    boolean checkAdmin(ResourcePageObservable observable) {
        String createBaseDN = observable.getCreateBaseDN();
        String entryDN = observable.getDN();
        if (entryDN != null) {
            DN dn1 = new DN(entryDN);
            DN dn2 = new DN(ADMIN_BASE_DN);
            return dn1.isDescendantOf(dn2);
        }
        else if (createBaseDN != null) {
            DN dn1 = new DN(createBaseDN);
            DN dn2 = new DN(ADMIN_BASE_DN);
            return dn1.equals(dn2);
        }
        return false;
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
        if (_firstName.getText().equals(_oldFirstName) == false) {
            if (_firstName.getText().trim().length() == 0) {
                observable.delete(ATTR_FIRST_NAME, _oldFirstName);
                _oldFirstName = "";
            } else {
                String newFirstName = _firstName.getText().trim();
                observable.replace(ATTR_FIRST_NAME, newFirstName);
                _oldFirstName = newFirstName;
            }
        }

        if (_lastName.getText().equals(_oldLastName) == false) {
            if (_lastName.getText().trim().length() == 0) {
                observable.delete(ATTR_LAST_NAME, _oldLastName);
                _oldLastName = "";
            } else {
                String newLastName = _lastName.getText().trim();
                observable.replace(ATTR_LAST_NAME, newLastName);
                _oldLastName = newLastName;
            }
        }

        if (_userID.getText().equals(_oldUserID) == false) {
            if (_userID.getText().trim().length() == 0) {
                observable.delete(ATTR_USER_ID, _oldUserID);
                _oldUserID = "";
            } else {
                String newUserID = _userID.getText().trim();
                observable.replace(ATTR_USER_ID, newUserID);
                _oldUserID = newUserID;
            }
        }

        if (_newPassword.getText().equals(_oldPassword) == false) {
            if (_newPassword.getText().trim().length() == 0) {
                observable.delete(ATTR_USER_PASSWORD, _oldPassword);
                _oldPassword = "";
            } else {
                String newPassword = _newPassword.getText().trim();
                observable.replace(ATTR_USER_PASSWORD, newPassword);
                _oldPassword = newPassword;
            }
        }

        Vector vTmp = new Vector();
        String trimmedFullName = _fullName.getText().trim();
        StringTokenizer st = new StringTokenizer(trimmedFullName, "\n\r");
        while (st.hasMoreTokens()) {
            vTmp.addElement(st.nextElement());
        }
        if (vTmp.size() == 0) {
            observable.delete(ATTR_FULL_NAME);
        } else {
            observable.replace(ATTR_FULL_NAME, vTmp);
        }

        vTmp.removeAllElements();
        st = new StringTokenizer(_email.getText(), "\n\r");
        while (st.hasMoreTokens()) {
            vTmp.addElement(st.nextElement());
        }
        if (vTmp.size() == 0) {
            observable.delete(ATTR_MAIL);
        } else {
            observable.replace(ATTR_MAIL, vTmp);
        }

        vTmp.removeAllElements();
        st = new StringTokenizer(_phone.getText(), "\n\r");
        while (st.hasMoreTokens()) {
            vTmp.addElement(st.nextElement());
        }
        if (vTmp.size() == 0) {
            observable.delete(ATTR_PHONE);
        } else {
            observable.replace(ATTR_PHONE, vTmp);
        }

        vTmp.removeAllElements();
        st = new StringTokenizer(_fax.getText(), "\n\r");
        while (st.hasMoreTokens()) {
            vTmp.addElement(st.nextElement());
        }
        if (vTmp.size() == 0) {
            observable.delete(ATTR_FAX);
        } else {
            observable.replace(ATTR_FAX, vTmp);
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
        _firstName.setText("");
        _lastName.setText("");
        _fullName.setText("");
        _userID.setText("");
        _email.setText("");
        _phone.setText("");
        _fax.setText("");
    }

    /**
     * Implements the IResourceEditorPage interface.
      * Sets default information on the page.
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
        boolean complete = ( (_lastName.getText().trim().length() > 0) &&
                             (_fullName.getText().trim().length() > 0) );

        if (_createNewUser ||
            (!_createNewUser && (_oldFirstName.length() > 0))) {
            complete &= (_firstName.getText().trim().length() > 0);
        }


        if (_isAdmin && _newPassword.getText().trim().length() == 0) {
            complete=false;
        }
        else if (_confirmPassword.getText().trim().length() > 0 ||
                _newPassword.getText().trim().length() > 0) {
            if (_newPassword.getText().trim().equals(
                    _confirmPassword.getText().trim()) == false) {
                SuiOptionPane.showMessageDialog(this,
                        _resource.getString("passwordPage",
                        "newpasswordmismatch-text"),
                        _resource.getString("passwordPage",
                        "newpasswordmismatch-title"),
                        SuiOptionPane.ERROR_MESSAGE);
                ModalDialogUtil.sleep();
                return false;
            }
        }

        if (complete == false) {
            SuiOptionPane.showMessageDialog(this,
                    _resource.getString("resourceEditor", "IncompleteText"),
                    _resource.getString("resourceEditor",
                    "IncompleteTitle"), SuiOptionPane.ERROR_MESSAGE);
            ModalDialogUtil.sleep();
        }

        return complete;
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
     * Implements the DocumentListener interface.
     * Handles auto-fill in for the fullname, email, and uid fields.
     *
     * @param e  document update event
     */
    public void insertUpdate(DocumentEvent e) {
        documentChange(e);
    }

    /**
     * Implements the DocumentListener interface.
     * Handles auto-fill in for the fullname and uid fields.
     *
     * @param e  document update event
     */
    public void removeUpdate(DocumentEvent e) {
        documentChange(e);
    }

    /**
     * Implements the DocumentListener interface.
     * Handles auto-fill in for the fullname and uid fields.
     *
     * @param e  document update event
     */
    public void changedUpdate(DocumentEvent e) {
        documentChange(e);
    }

    /**
     * Handles auto-fill in for the fullname and uid fields.
     *
     * @param e  document update event
     */
    private void documentChange(DocumentEvent e) {
        if (_fFillFullName) {
            if (e.getDocument() == _fullName.getDocument()) {
                _fFillFullName = false;
            } else {
                updateFullname();
            }
        }
        if (_fUpdateUID) {
            if (e.getDocument() == _userID.getDocument()) {
                _fUpdateUID = false;
            } else {
                updateUID();
            }
        }
    }

    /**
     * Auto-fills fullname field.
     */
    void updateFullname() {
        String name = _firstName.getText() + " " + _lastName.getText();
        _fullNameDoc.removeDocumentListener(this);
        int iStart = 0;
        int iEnd = 0;
        try {
            iStart = _fullName.getLineStartOffset(0);
            iEnd = _fullName.getLineEndOffset(0);
        } catch (Exception e) {

        }
        iEnd--;
        if ((iStart == -1) || (iEnd < 1)) {
            _fullName.setText(name);
        } else {
            _fullName.replaceRange(name, iStart, iEnd);
        }
        _fullNameDoc.addDocumentListener(this);
    }

    /**
     * Auto-fills uid field as long as no UTF8 characters are specified.
     * If the administrator specifically types in the UTF8 characters into
     * the field, it is accepted. However, since some servers do not support
     * UTF8 for email addresses, this auto-fill in feature is purposely
     * disabled to disallow these characters.
     */
    void updateUID() {
        String sUID = "";
        _userIDDoc.removeDocumentListener(this);
        if (_sSystemUID != null) {
            if (_sSystemUID.equalsIgnoreCase("ntUserDomainID") &&
                    _observable != null) {
                sUID = _observable.get("ntUserDomainID",0);
                int iColon = sUID.indexOf(':');
                if (iColon > 0) {
                    sUID = sUID.substring(iColon + 1);
                }
            } else if (_sSystemUID.equalsIgnoreCase(ID_FORMAT_MAIL) &&
                    _observable != null) {
                sUID = _observable.get(ID_FORMAT_MAIL, 0);
            } else if ( _sSystemUID.equalsIgnoreCase(
                    ID_FORMAT_FIRSTLETTER_LASTNAME)) {
                String firstName = _firstName.getText();
                if (firstName.length() > 0) {
                    sUID = _firstName.getText().substring(0, 1) +
                            _lastName.getText();
                } else {
                    sUID = _lastName.getText();
                }
            } else if ( _sSystemUID.equalsIgnoreCase(
                    ID_FORMAT_GIVENNAME_FIRSTLETTER)) {
                String lastName = _lastName.getText();
                if (lastName.length() > 0) {
                    sUID = _firstName.getText() +
                            _lastName.getText().substring(0, 1);
                } else {
                    sUID = _firstName.getText();
                }
            } else if ( _sSystemUID.equalsIgnoreCase(
                    ID_FORMAT_GIVENNAME_LASTNAME)) {
                sUID = _firstName.getText() + _lastName.getText();
            } else if ( _sSystemUID.equalsIgnoreCase(
                    ID_FORMAT_LASTNAME_GIVENNAME)) {
                sUID = _lastName.getText() + _firstName.getText();
            } else if (_observable != null) {
                sUID = _observable.get(_sSystemUID, 0);
            }
        } else {
            sUID = _firstName.getText() + _lastName.getText();
        }

        if (containsUTF8(sUID) == false) {
            _userID.setText(sUID);
        }

        _userIDDoc.addDocumentListener(this);
    }


    /**
     * Determines whether the specified string contains UTF8 characters.
      *
      * @param value  string to test
      * @return       true if the string contains UTF8 characters; false otherwise
     */
    private boolean containsUTF8(String value) {
        byte[] byteValue = value.getBytes();
        for (int i = 0; i < byteValue.length; i++) {
            if ((byteValue[i] & 0x7f) != byteValue[i]) {
                return true;
            }
        }
        return false;
    }


    /**
     * Implements the IResourceEditorPage interface.
      * Displays help information for the page
     */
    public void help() {
        Help help = new Help(_resource);
        help.contextHelp("ug", "ResEditorUserPageDef");
    }
}
