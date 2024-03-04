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

import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.SuiLookAndFeel;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.text.*;


/**
 * UserLanguageFactory generates language pages for the user resource editor.
 *
 * @see LanguagePage
 * @see ILanguageFactory
 */
class UserLanguageFactory implements ILanguageFactory {
    PickerEditorResourceSet _resource = new PickerEditorResourceSet();
    int iCount = Integer.parseInt(_resource.getString("userPage","pluginCount"));
    ResEditorUserPageGeneralLang[] langs;

    /**
    * Constructor. Creates as many language pages as specified in the property file.
    */
    public UserLanguageFactory() {
        langs = new ResEditorUserPageGeneralLang[iCount];
        for (int i = 0; i < iCount; i++) {
            langs[i] = null;
        }
    }

    /**
     * Implements ILanguageFactory interface. Returns the page for the specified
     * language.
     *
     * @param language  the language page to retrieve
     * @return          the language page to retrieve
     */
    public IResourceEditorPage getPage(String sLanguage) {
        for (int i = 0; i < iCount; i++) {
            if (sLanguage.equals(
                    _resource.getString("userPage", "plugin"+i))) {
                if (langs[i] == null) {
                    String sPhonetic = _resource.getString("userPage","phonetic"+i);
                    if (sPhonetic.equalsIgnoreCase("true"))
                        langs[i] = new ResEditorUserPageGeneralLang(
                                _resource.getString("userPage",
                                "plugin"+i), "ResEditorUserPageLangWP",
                                true, _resource.getString("userPage","order"+i));
                    else
                        langs[i] = new ResEditorUserPageGeneralLang(
                                _resource.getString("userPage",
                                "plugin"+i), "ResEditorUserPageLang",
                                false, _resource.getString("userPage","order"+i));
                }
                return langs[i];
            }
        }
        return null;
    }
}


/**
  * ResEditorUserPageGeneralLang is the IResourceEditorPage that the
  * UserLanguageFactory generates. Phonetic fields are created depending
  * on the language.
  */
class ResEditorUserPageGeneralLang extends JPanel implements IResourceEditorPage,
Observer, DocumentListener, ILocalize {
    private String ID;

    JTextField _firstName;
    JTextField _lastName;
    JTextArea _fullName1;
    JTextArea _phone;
    JTextField _phoneticFirstName;
    JTextField _phoneticLastName;
    JTextArea _phoneticFullName1;

    String _oldFirstName, _oldLastName;
    String _oldPhoneticFirstName, _oldPhoneticLastName;

    String _sLangTag;
    String _sFirstName;
    String _sLastName;
    String _sFullName1;
    String _sPhone;
    String _sPhoneticFirstName;
    String _sPhoneticLastName;
    String _sPhoneticFullName1;

    boolean _isModified = false;
    boolean _isReadOnly = false;
    boolean _isEnable = true;
    boolean _isPhonetic = false;
    boolean _isFirstLast = true;

    boolean _createNewUser;

    boolean _fFillFullName;
    int _iFullnameFormat;
    Document _fullNameDoc;

    boolean _fFillPhoneticFullName;
    int _iPhoneticFullnameFormat;
    Document _phoneticFullNameDoc;

    String _sHelp;

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
                               ResEditorUserPageGeneralLang.this);
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
                        _observable.replace(_sFirstName,
                                _firstName.getText());
                        vTmp.removeAllElements();
                        StringTokenizer st = new StringTokenizer(
                                _fullName1.getText(), "\n\r");
                        while (st.hasMoreTokens()) {
                            vTmp.addElement(st.nextElement());
                        }
                        _observable.replace(_sFullName1, vTmp);
                    } else if (src == _lastName) {
                        _observable.replace(_sLastName,
                                _lastName.getText());
                        vTmp.removeAllElements();
                        StringTokenizer st = new StringTokenizer(
                                _fullName1.getText(), "\n\r");
                        while (st.hasMoreTokens()) {
                            vTmp.addElement(st.nextElement());
                        }
                        _observable.replace(_sFullName1, vTmp);
                    } else if (src == _fullName1) {
                        vTmp.removeAllElements();
                        StringTokenizer st = new StringTokenizer(
                                _fullName1.getText(), "\n\r");
                        while (st.hasMoreTokens()) {
                            vTmp.addElement(st.nextElement());
                        }
                        _observable.replace(_sFullName1, vTmp);
                    } else if (src == _phone) {
                        vTmp.removeAllElements();
                        StringTokenizer st =
                                new StringTokenizer(_phone.getText(),
                                "\n\r");
                        while (st.hasMoreTokens()) {
                            vTmp.addElement(st.nextElement());
                        }
                        _observable.replace(_sPhone, vTmp);
                    } else if (src == _phoneticFirstName) {
                        _observable.replace(_sPhoneticFirstName,
                                _phoneticFirstName.getText());
                        vTmp.removeAllElements();
                        StringTokenizer st = new StringTokenizer(
                                _phoneticFullName1.getText(), "\n\r");
                        while (st.hasMoreTokens()) {
                            vTmp.addElement(st.nextElement());
                        }
                        _observable.replace(_sPhoneticFullName1, vTmp);
                    } else if (src == _phoneticLastName) {
                        _observable.replace(_sPhoneticLastName,
                                _phoneticLastName.getText());
                        vTmp.removeAllElements();
                        StringTokenizer st = new StringTokenizer(
                                _phoneticFullName1.getText(), "\n\r");
                        while (st.hasMoreTokens()) {
                            vTmp.addElement(st.nextElement());
                        }
                        _observable.replace(_sPhoneticFullName1, vTmp);
                    } else if (src == _phoneticFullName1) {
                        vTmp.removeAllElements();
                        StringTokenizer st = new StringTokenizer(
                                _phoneticFullName1.getText(), "\n\r");
                        while (st.hasMoreTokens()) {
                            vTmp.addElement(st.nextElement());
                        }
                        _observable.replace(_sPhoneticFullName1, vTmp);
                    }
                }
            };


    /**
    * Constructor
    *
    * @param sLangTag    the language this plugin refers to
    * @param sHelp       the help for this plugin
    * @param isPhonetic  specifies whether to create the phonetic fields
    * @param sOrder      order of given name and surname
    */
    public ResEditorUserPageGeneralLang(String sLangTag, String sHelp,
            boolean isPhonetic, String sOrder) {
        super(true);

        _sLangTag = sLangTag;
        _sFirstName = "givenname;lang-" + sLangTag;
        _sLastName = "sn;lang-" + sLangTag;
        _sFullName1 = "cn;lang-" + sLangTag;
        _sPhone = "telephoneNumber;lang-" + sLangTag;
        _sPhoneticFirstName = "givenname;phonetic;lang-" + sLangTag;
        _sPhoneticLastName = "sn;phonetic;lang-" + sLangTag;
        _sPhoneticFullName1 = "cn;phonetic;lang-" + sLangTag;
        _sHelp = sHelp;
        _isPhonetic = isPhonetic;
        if (sOrder.equalsIgnoreCase("lastname_firstname"))
            _isFirstLast = false;
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
            if (argString.equalsIgnoreCase(_sFirstName)) {
                _firstName.setText(observable.get(_sFirstName, 0));
            } else if (argString.equalsIgnoreCase(_sLastName)) {
                _lastName.setText(observable.get(_sLastName, 0));
            } else if (argString.equalsIgnoreCase(_sFullName1)) {
                _fullName1.setText("");
                Vector vFullname = observable.get(_sFullName1);
                Enumeration eFullname = vFullname.elements();
                if (eFullname.hasMoreElements()) {
                    _fullName1.append((String) eFullname.nextElement());
                }
                while (eFullname.hasMoreElements()) {
                    _fullName1.append("\n" + eFullname.nextElement());
                }
            } else if (argString.equalsIgnoreCase(_sPhone)) {
                _phone.setText("");
                Vector vPhone = observable.get(_sPhone);
                Enumeration ePhone = vPhone.elements();
                if (ePhone.hasMoreElements()) {
                    _phone.append((String) ePhone.nextElement());
                }
                while (ePhone.hasMoreElements()) {
                    _phone.append("\n" + ePhone.nextElement());
                }
            } else if (argString.equalsIgnoreCase(_sPhoneticFirstName)) {
                _phoneticFirstName.setText(
                        observable.get(_sPhoneticFirstName, 0));
            } else if (argString.equalsIgnoreCase(_sPhoneticLastName)) {
                _phoneticLastName.setText(
                        observable.get(_sPhoneticLastName, 0));
            } else if (argString.equalsIgnoreCase(_sPhoneticFullName1)) {
                _phoneticFullName1.setText("");
                Vector vFullname = observable.get(_sPhoneticFullName1);
                Enumeration eFullname = vFullname.elements();
                if (eFullname.hasMoreElements()) {
                    _phoneticFullName1.append(
                            (String) eFullname.nextElement());
                }
                while (eFullname.hasMoreElements()) {
                    _phoneticFullName1.append("\n" +
                            eFullname.nextElement());
                }
            }
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
        int row = 0;
        _createNewUser = observable.isNewUser();

        JLabel lblName1, lblName2, lblFullName, lblPhone;
        JLabel lblPhonetic, lblPhoneticName1, lblPhoneticName2, lblPhoneticFullName;

        PickerEditorResourceSet resource = new PickerEditorResourceSet();
        ID = resource.getString("userPage", _sLangTag);

        JPanel p = new JPanel(new GridBagLayout());
        if (_isFirstLast) {
            lblName1 =
                new JLabel(resource.getString("userPage", "firstNameWNoStar"),
                           JLabel.RIGHT);
            GridBagUtil.constrain(p, lblName1, 0, row, 1, 1, 0.0, 0.0,
                    GridBagConstraints.NORTHWEST,
                    GridBagConstraints.HORIZONTAL,
                    SuiLookAndFeel.VERT_WINDOW_INSET,
                    SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);

            _firstName = new JTextField();
            lblName1.setLabelFor(_firstName);
            GridBagUtil.constrain(p, _firstName, 1, row,
                    GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                    GridBagConstraints.NORTHWEST,
                    GridBagConstraints.HORIZONTAL,
                    SuiLookAndFeel.VERT_WINDOW_INSET,
                    SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0,
                    SuiLookAndFeel.HORIZ_WINDOW_INSET);

            row++;

            lblName2 =
                    new JLabel(resource.getString("userPage", "lastNameWNoStar"),
                    JLabel.RIGHT);
            GridBagUtil.constrain(p, lblName2, 0, row, 1, 1, 0.0, 0.0,
                    GridBagConstraints.NORTHWEST,
                    GridBagConstraints.HORIZONTAL,
                    SuiLookAndFeel.COMPONENT_SPACE,
                    SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);

            _lastName = new JTextField();
            lblName2.setLabelFor(_lastName);
            GridBagUtil.constrain(p, _lastName, 1, row,
                    GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                    GridBagConstraints.NORTHWEST,
                    GridBagConstraints.HORIZONTAL,
                    SuiLookAndFeel.COMPONENT_SPACE,
                    SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0,
                    SuiLookAndFeel.HORIZ_WINDOW_INSET);

            row++;
        } else {
            lblName1 =
                    new JLabel(resource.getString("userPage", "lastNameWNoStar"),
                    JLabel.RIGHT);
            GridBagUtil.constrain(p, lblName1, 0, row, 1, 1, 0.0, 0.0,
                    GridBagConstraints.NORTHWEST,
                    GridBagConstraints.HORIZONTAL,
                    SuiLookAndFeel.VERT_WINDOW_INSET,
                    SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);

            _lastName = new JTextField();
            lblName1.setLabelFor(_lastName);
            GridBagUtil.constrain(p, _lastName, 1, row,
                    GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                    GridBagConstraints.NORTHWEST,
                    GridBagConstraints.HORIZONTAL,
                    SuiLookAndFeel.VERT_WINDOW_INSET,
                    SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0,
                    SuiLookAndFeel.HORIZ_WINDOW_INSET);

            row++;

            lblName2 =
                    new JLabel(resource.getString("userPage", "firstNameWNoStar"),
                    JLabel.RIGHT);
            GridBagUtil.constrain(p, lblName2, 0, row, 1, 1, 0.0, 0.0,
                    GridBagConstraints.NORTHWEST,
                    GridBagConstraints.HORIZONTAL,
                    SuiLookAndFeel.COMPONENT_SPACE,
                    SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);
            
            _firstName = new JTextField();
            lblName2.setLabelFor(_firstName);
            GridBagUtil.constrain(p, _firstName, 1, row,
                    GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                    GridBagConstraints.NORTHWEST,
                    GridBagConstraints.HORIZONTAL,
                    SuiLookAndFeel.COMPONENT_SPACE,
                    SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0,
                    SuiLookAndFeel.HORIZ_WINDOW_INSET);

            row++;
        }

        lblFullName =
                new JLabel(resource.getString("userPage", "fullNameWNoStar"),
                JLabel.RIGHT);
        GridBagUtil.constrain(p, lblFullName, 0, row, 1, 1, 0.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);

        _fullName1 = new UGTextArea();
        lblFullName.setLabelFor(lblFullName);
        GridBagUtil.constrain(p, _fullName1, 1, row,
                GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.BOTH,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0,
                SuiLookAndFeel.HORIZ_WINDOW_INSET);

        row++;

        lblPhone = new JLabel(resource.getString("userPage", "phone"),
                JLabel.RIGHT);
        GridBagUtil.constrain(p, lblPhone, 0, row, 1, 1, 0.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);

        _phone = new UGTextArea();
        lblPhone.setLabelFor(_phone);
        GridBagUtil.constrain(p, _phone, 1, row,
                GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.BOTH,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0,
                SuiLookAndFeel.HORIZ_WINDOW_INSET);

        row++;

        Vector vFullname = observable.get(_sFullName1);
        Enumeration eFullname = vFullname.elements();
        if (eFullname.hasMoreElements()) {
            _fullName1.append((String) eFullname.nextElement());
        }
        while (eFullname.hasMoreElements()) {
            _fullName1.append("\n" + eFullname.nextElement());
        }

        _fullNameDoc = _fullName1.getDocument();
        _fullNameDoc.addDocumentListener(this);
        _fFillFullName = false;

        if (vFullname.size() == 0) {
            _fFillFullName = true;
        }

        _oldLastName = observable.get(_sLastName, 0);
        _lastName.setText(_oldLastName);
        Document doc = _lastName.getDocument();
        doc.addDocumentListener(this);

        _oldFirstName = observable.get(_sFirstName, 0);
        _firstName.setText(_oldFirstName);
        doc = _firstName.getDocument();
        doc.addDocumentListener(this);

        Vector vPhone = observable.get(_sPhone);
        Enumeration ePhone = vPhone.elements();
        if (ePhone.hasMoreElements()) {
            _phone.append((String) ePhone.nextElement());
        }
        while (ePhone.hasMoreElements()) {
            _phone.append("\n" + ePhone.nextElement());
        }

        _firstName.addFocusListener(_focusAdaptor);
        _lastName.addFocusListener(_focusAdaptor);
        _fullName1.addFocusListener(_focusAdaptor);
        _phone.addFocusListener(_focusAdaptor);

        // phonetic
        if (_isPhonetic) {
            lblPhonetic = new JLabel(resource.getString("userPage", "phonetic"),
                    JLabel.LEFT);
            GridBagUtil.constrain(p, lblPhonetic, 1, row, 1, 1, 0.0, 0.0,
                    GridBagConstraints.NORTHWEST,
                    GridBagConstraints.HORIZONTAL,
                    SuiLookAndFeel.SEPARATED_COMPONENT_SPACE,
                    SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);

            row++;

            if (_isFirstLast) {
                lblPhoneticName1 =
                        new JLabel(resource.getString("userPage", "firstNameWNoStar"),
                        JLabel.RIGHT);
                GridBagUtil.constrain(p, lblPhoneticName1, 0, row, 1, 1, 0.0,
                        0.0, GridBagConstraints.NORTHWEST,
                        GridBagConstraints.HORIZONTAL,
                        SuiLookAndFeel.COMPONENT_SPACE,
                        SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);

                _phoneticFirstName = new JTextField();
                GridBagUtil.constrain(p, _phoneticFirstName, 1, row,
                        GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                        GridBagConstraints.NORTHWEST,
                        GridBagConstraints.HORIZONTAL,
                        SuiLookAndFeel.COMPONENT_SPACE,
                        SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0,
                        SuiLookAndFeel.HORIZ_WINDOW_INSET);

                row++;

                lblPhoneticName2 =
                        new JLabel(resource.getString("userPage", "lastNameWNoStar"),
                        JLabel.RIGHT);
                GridBagUtil.constrain(p, lblPhoneticName2, 0, row, 1, 1, 0.0,
                        0.0, GridBagConstraints.NORTHWEST,
                        GridBagConstraints.HORIZONTAL,
                        SuiLookAndFeel.COMPONENT_SPACE,
                        SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);

                _phoneticLastName = new JTextField();
                GridBagUtil.constrain(p, _phoneticLastName, 1, row,
                        GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                        GridBagConstraints.NORTHWEST,
                        GridBagConstraints.HORIZONTAL,
                        SuiLookAndFeel.COMPONENT_SPACE,
                        SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0,
                        SuiLookAndFeel.HORIZ_WINDOW_INSET);

                row++;
            } else {
                lblPhoneticName1 =
                        new JLabel(resource.getString("userPage", "lastNameWNoStar"),
                        JLabel.RIGHT);
                GridBagUtil.constrain(p, lblPhoneticName1, 0, row, 1, 1, 0.0,
                        0.0, GridBagConstraints.NORTHWEST,
                        GridBagConstraints.HORIZONTAL,
                        SuiLookAndFeel.COMPONENT_SPACE,
                        SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);

                _phoneticLastName = new JTextField();
                GridBagUtil.constrain(p, _phoneticLastName, 1, row,
                        GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                        GridBagConstraints.NORTHWEST,
                        GridBagConstraints.HORIZONTAL,
                        SuiLookAndFeel.COMPONENT_SPACE,
                        SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0,
                        SuiLookAndFeel.HORIZ_WINDOW_INSET);

                row++;

                lblPhoneticName2 =
                        new JLabel(resource.getString("userPage", "firstNameWNoStar"),
                        JLabel.RIGHT);
                GridBagUtil.constrain(p, lblPhoneticName2, 0, row, 1, 1, 0.0,
                        0.0, GridBagConstraints.NORTHWEST,
                        GridBagConstraints.HORIZONTAL,
                        SuiLookAndFeel.COMPONENT_SPACE,
                        SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);

                _phoneticFirstName = new JTextField();
                GridBagUtil.constrain(p, _phoneticFirstName, 1, row,
                        GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                        GridBagConstraints.NORTHWEST,
                        GridBagConstraints.HORIZONTAL,
                        SuiLookAndFeel.COMPONENT_SPACE,
                        SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0,
                        SuiLookAndFeel.HORIZ_WINDOW_INSET);

                row++;
            }

            lblPhoneticFullName =
                    new JLabel(resource.getString("userPage", "fullNameWNoStar"),
                    JLabel.RIGHT);
            GridBagUtil.constrain(p, lblPhoneticFullName, 0, row, 1, 1, 0.0, 0.0,
                    GridBagConstraints.NORTHWEST,
                    GridBagConstraints.HORIZONTAL,
                    SuiLookAndFeel.COMPONENT_SPACE,
                    SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);

            _phoneticFullName1 = new UGTextArea();
            GridBagUtil.constrain(p, _phoneticFullName1, 1, row,
                    GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                    GridBagConstraints.NORTHWEST, GridBagConstraints.BOTH,
                    SuiLookAndFeel.COMPONENT_SPACE,
                    SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0,
                    SuiLookAndFeel.HORIZ_WINDOW_INSET);

            row++;

            vFullname = observable.get(_sPhoneticFullName1);
            eFullname = vFullname.elements();
            if (eFullname.hasMoreElements()) {
                _phoneticFullName1.append(
                        (String) eFullname.nextElement());
            }
            while (eFullname.hasMoreElements()) {
                _phoneticFullName1.append("\n" + eFullname.nextElement());
            }

            _phoneticFullNameDoc = _phoneticFullName1.getDocument();
            _phoneticFullNameDoc.addDocumentListener(this);
            _fFillPhoneticFullName = false;

            if (vFullname.size() == 0) {
                _fFillPhoneticFullName = true;
            }

            _oldPhoneticLastName = observable.get(_sPhoneticLastName, 0);
            _phoneticLastName.setText(_oldPhoneticLastName);
            Document pdoc = _phoneticLastName.getDocument();
            pdoc.addDocumentListener(this);

            _oldPhoneticFirstName = observable.get(_sPhoneticFirstName, 0);
            _phoneticFirstName.setText(_oldPhoneticFirstName);
            pdoc = _phoneticFirstName.getDocument();
            pdoc.addDocumentListener(this);

            _phoneticFirstName.addFocusListener(_focusAdaptor);
            _phoneticLastName.addFocusListener(_focusAdaptor);
            _phoneticFullName1.addFocusListener(_focusAdaptor);
        }

        JLabel blankLabel = new JLabel("");
        GridBagUtil.constrain(p, blankLabel, 0, row,
                GridBagConstraints.REMAINDER,
                GridBagConstraints.REMAINDER, 1.0, 1.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.BOTH,
                SuiLookAndFeel.SEPARATED_COMPONENT_SPACE,
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

        if (!(_firstName.getText().equals(_oldFirstName))) {
            if (_firstName.getText().equals("")) {
                observable.delete(_sFirstName, _oldFirstName);
                _oldFirstName = "";
            } else {
                observable.replace(_sFirstName, _firstName.getText());
                _oldFirstName = _firstName.getText();
            }
        }

        if (!(_lastName.getText().equals(_oldLastName))) {
            if (_lastName.getText().equals("")) {
                observable.delete(_sLastName, _oldLastName);
                _oldLastName = "";
            } else {
                observable.replace(_sLastName, _lastName.getText());
                _oldLastName = _lastName.getText();
            }
        }

        Vector vTmp = new Vector();
        StringTokenizer st =
                new StringTokenizer(_fullName1.getText(), "\n\r");
        while (st.hasMoreTokens()) {
            vTmp.addElement(st.nextElement());
        }
        if (vTmp.size() == 0) {
            observable.delete(_sFullName1);
        } else {
            observable.replace(_sFullName1, vTmp);
        }

        vTmp.removeAllElements();
        st = new StringTokenizer(_phone.getText(), "\n\r");
        while (st.hasMoreTokens()) {
            vTmp.addElement(st.nextElement());
        }
        if (vTmp.size() == 0) {
            observable.delete(_sPhone);
        } else {
            observable.replace(_sPhone, vTmp);
        }

        if (_isPhonetic) {
            if (!(_phoneticFirstName.getText().equals(
                    _oldPhoneticFirstName))) {
                if (_phoneticFirstName.getText().equals("")) {
                    observable.delete(_sPhoneticFirstName,
                            _oldPhoneticFirstName);
                    _oldPhoneticFirstName = "";
                } else {
                    observable.replace(_sPhoneticFirstName,
                            _phoneticFirstName.getText());
                    _oldPhoneticFirstName = _phoneticFirstName.getText();
                }
            }

            if (!(_phoneticLastName.getText().equals(
                    _oldPhoneticLastName))) {
                if (_phoneticLastName.getText().equals("")) {
                    observable.delete(_sPhoneticLastName,
                            _oldPhoneticLastName);
                    _oldPhoneticLastName = "";
                } else {
                    observable.replace(_sPhoneticLastName,
                            _phoneticLastName.getText());
                    _oldPhoneticLastName = _phoneticLastName.getText();
                }
            }

            vTmp.removeAllElements();
            st = new StringTokenizer(_phoneticFullName1.getText(), "\n\r");
            while (st.hasMoreTokens()) {
                vTmp.addElement(st.nextElement());
            }
            if (vTmp.size() == 0) {
                observable.delete(_sPhoneticFullName1);
            } else {
                observable.replace(_sPhoneticFullName1, vTmp);
            }
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
        _firstName.setText("");
        _lastName.setText("");
        _fullName1.setText("");
        _phone.setText("");
        if (_isPhonetic) {
            _phoneticFirstName.setText("");
            _phoneticLastName.setText("");
            _phoneticFullName1.setText("");
        }
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
        // every language page is optional
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
     * Implements the DocumentListener interface.
     * Handles auto-fill in for the fullname and phonetic fullname fields.
     *
     * @param e  document update event
     */
    public void insertUpdate(DocumentEvent e) {

        if (e.getDocument() == _fullName1.getDocument()) {
            _fFillFullName = false;
        }
        if (_isPhonetic && e.getDocument() == _phoneticFullName1.getDocument()) {
            _fFillPhoneticFullName = false;
        }

        if (_fFillFullName) {
            if (e.getDocument() != _fullName1.getDocument()) {
                updateFullname();
            }
        }
        if (_isPhonetic && _fFillPhoneticFullName) {
            if (e.getDocument() != _phoneticFullName1.getDocument()) {
                updatePhoneticFullname();
            }
        }
    }

    /**
     * Implements the DocumentListener interface.
     * Handles auto-fill in for the fullname and phonetic fullname fields.
     *
     * @param e  document update event
     */
    public void removeUpdate(DocumentEvent e) {

        if (e.getDocument() == _fullName1.getDocument()) {
            _fFillFullName = false;
        }
        if (_isPhonetic && e.getDocument() == _phoneticFullName1.getDocument()) {
            _fFillPhoneticFullName = false;
        }

        if (_fFillFullName) {
            if (e.getDocument() != _fullName1.getDocument()) {
                updateFullname();
            }
        }
        if (_isPhonetic && _fFillPhoneticFullName) {
            if (e.getDocument() != _phoneticFullName1.getDocument()) {
                updatePhoneticFullname();
            }
        }
    }

    /**
     * Implements the DocumentListener interface.
     * Handles auto-fill in for the fullname and phonetic fullname fields.
     *
     * @param e  document update event
     */
    public void changedUpdate(DocumentEvent e) {
                
        if (_fFillFullName) {
            if (e.getDocument() != _fullName1.getDocument()) {
                updateFullname();
            }
        }
        if (_isPhonetic && _fFillPhoneticFullName) {
            if (e.getDocument() != _phoneticFullName1.getDocument()) {
                updatePhoneticFullname();
            }
        }
    }

    /**
     * Handles auto-fill in for the fullname field.
     */
    void updateFullname() {
        String name;
        if (_isFirstLast)
            name = _firstName.getText() + " "+_lastName.getText();
        else
            name = _lastName.getText() + " "+_firstName.getText();
        _fullNameDoc.removeDocumentListener(this);
        int iStart = 0;
        int iEnd = 0;
        try {
            iStart = _fullName1.getLineStartOffset(0);
            iEnd = _fullName1.getLineEndOffset(0);
        } catch (Exception e) {

        }
        iEnd--;
        if ((iStart == -1) || (iEnd < 1)) {
            _fullName1.setText(name);
        } else {
            _fullName1.replaceRange(name, iStart, iEnd);
        }
        _fullNameDoc.addDocumentListener(this);
    }

    /**
     * Handles auto-fill in for the phonetic fullname field.
     */
    void updatePhoneticFullname() {
        String name = _phoneticLastName.getText() + " "+
                _phoneticFirstName.getText();
        _phoneticFullNameDoc.removeDocumentListener(this);
        int iStart = 0;
        int iEnd = 0;
        try {
            iStart = _phoneticFullName1.getLineStartOffset(0);
            iEnd = _phoneticFullName1.getLineEndOffset(0);
        } catch (Exception e) {

        }
        iEnd--;
        if ((iStart == -1) || (iEnd < 1)) {
            _phoneticFullName1.setText(name);
        } else {
            _phoneticFullName1.replaceRange(name, iStart, iEnd);
        }
        _phoneticFullNameDoc.addDocumentListener(this);
    }

    /**
     * Implements the IResourceEditorPage interface.
      * Displays help information for the page
     */
    public void help() {
        PickerEditorResourceSet _resource = new PickerEditorResourceSet();
        Help help = new Help(_resource);

        help.contextHelp("ug",_sHelp);
    }

    boolean _fLocalize = false;

    /**
    * Implements the ILocalize interface. This determines whether localized
    * information is available for the language.
    *
    * @return  true if localized information is available; false otherwise
    */
    public boolean isLocalize() {
        return _fLocalize;
    }

    public void setLocalize(boolean fLocalize) {
        _fLocalize = fLocalize;
    }
}
