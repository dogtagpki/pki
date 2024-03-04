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


/**
 * OULanguageFactory generates language pages for the ou resource editor.
 *
 * @see LanguagePage
 * @see ILanguageFactory
 */
class OULanguageFactory implements ILanguageFactory {
    PickerEditorResourceSet _resource = new PickerEditorResourceSet();
    int iCount = Integer.parseInt(_resource.getString("OUPage","pluginCount"));
    ResEditorOUPageGeneralLang[] langs;

    /**
    * Constructor. Creates as many language pages as specified in the property file.
    */
    public OULanguageFactory() {
        langs = new ResEditorOUPageGeneralLang[iCount];
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
                    _resource.getString("OUPage", "plugin"+i))) {
                if (langs[i] == null) {
                    String sPhonetic = _resource.getString("OUPage","phonetic"+i);
                    if (sPhonetic.equalsIgnoreCase("true"))
                        langs[i] = new ResEditorOUPageGeneralLang(
                                _resource.getString("OUPage",
                                "plugin"+i), "ResEditorOUPageLangWP", true);
                    else
                        langs[i] = new ResEditorOUPageGeneralLang(
                                _resource.getString("OUPage",
                                "plugin"+i), "ResEditorOUPageLang", false);
                }
                return langs[i];
            }
        }
        return null;
    }
}


/**
  * ResEditorOUPageGeneralLang is the IResourceEditorPage that the
  * OULanguageFactory generates. Phonetic fields are created depending
  * on the language.
  */
class ResEditorOUPageGeneralLang extends JPanel implements IResourceEditorPage,
Observer, ILocalize {
    PickerEditorResourceSet _resource = new PickerEditorResourceSet();

    private String ID;

    JTextField _tfName;
    JTextArea _tfDescription;
    JTextArea _tfPhone;
    JTextArea _tfFax;
    JTextArea _tfAddress;
    JTextArea _tfAlias;
    JTextField _tfPhoneticName;
    JTextArea _tfPhoneticAddress;

    boolean _isModified = false;
    boolean _isReadOnly = false;
    boolean _isEnable = true;
    boolean _isPhonetic = false;

    String _oldName;
    String _oldPhoneticName;

    String _sOU;
    String _sDesc;
    String _sPhone;
    String _sFax;
    String _sAddr;
    String _sAlias;
    String _sPhoneticOU;
    String _sPhoneticAddr;
    String _sLangTag;
    String _sHelp;

    static final String _aliasObjectClass = "alias";

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
                                        ResEditorOUPageGeneralLang.this);
                    if(w != null && w.getFocusOwner() == null) {
                        return;
                    }
 
                    Vector vTmp = new Vector();
                    if (_observable == null) {
                        return;
                    }
                    Component src = e.getComponent();
                    if (src == _tfName) {
                        _observable.replace(_sOU, _tfName.getText());
                    } else if (src == _tfDescription) {
                        vTmp.removeAllElements();
                        StringTokenizer st = new StringTokenizer(
                                _tfDescription.getText(), "\n\r");
                        while (st.hasMoreTokens()) {
                            vTmp.addElement(st.nextElement());
                        }
                        _observable.replace(_sDesc, vTmp);
                    } else if (src == _tfPhone) {
                        vTmp.removeAllElements();
                        StringTokenizer st = new StringTokenizer(
                                _tfPhone.getText(), "\n\r");
                        while (st.hasMoreTokens()) {
                            vTmp.addElement(st.nextElement());
                        }
                        _observable.replace(_sPhone, vTmp);
                    } else if (src == _tfFax) {
                        vTmp.removeAllElements();
                        StringTokenizer st =
                                new StringTokenizer(_tfFax.getText(),
                                "\n\r");
                        while (st.hasMoreTokens()) {
                            vTmp.addElement(st.nextElement());
                        }
                        _observable.replace(_sFax, vTmp);
                    } else if (src == _tfAddress) {
                        vTmp.removeAllElements();
                        StringTokenizer st = new StringTokenizer(
                                _tfAddress.getText(), "\n\r");
                        while (st.hasMoreTokens()) {
                            vTmp.addElement(st.nextElement());
                        }
                        _observable.replace(_sAddr, vTmp);
                    } else if (src == _tfAlias) {
                        vTmp.removeAllElements();
                        StringTokenizer st = new StringTokenizer(
                                _tfAlias.getText(), "\n\r");
                        while (st.hasMoreTokens()) {
                            vTmp.addElement(st.nextElement());
                        }
                        if (vTmp.size() != 0) {
                            boolean fContain = false;

                            Vector vOC = _observable.get("ObjectClass");
                            Enumeration eOC = vOC.elements();
                            while (eOC.hasMoreElements()) {
                                String sOC = (String) eOC.nextElement();
                                if (sOC.equalsIgnoreCase(
                                        _aliasObjectClass)) {
                                    fContain = true;
                                    break;
                                }
                            }

                            if (!fContain) {
                                vOC.addElement(_aliasObjectClass);
                                _observable.replace("ObjectClass", vOC);
                            }
                            _observable.replace(_sAlias, vTmp);
                        }
                    } else if (src == _tfPhoneticName) {
                        _observable.replace(_sPhoneticOU,
                                _tfPhoneticName.getText());
                    } else if (src == _tfPhoneticAddress) {
                        vTmp.removeAllElements();
                        StringTokenizer st = new StringTokenizer(
                                _tfPhoneticAddress.getText(), "\n\r");
                        while (st.hasMoreTokens()) {
                            vTmp.addElement(st.nextElement());
                        }
                        _observable.replace(_sPhoneticAddr, vTmp);
                    }
                }
            };


    /**
    * Constructor
    *
    * @param sLangTag    the language this plugin refers to
    * @param sHelp       the help for this plugin
    * @param isPhonetic  specifies whether to create the phonetic fields
    */
    public ResEditorOUPageGeneralLang(String sLangTag, String sHelp,
            boolean isPhonetic) {
        super(true);

        _sLangTag = sLangTag;
        _sOU = "ou;lang-" + sLangTag;
        _sDesc = "description;lang-" + sLangTag;
        _sPhone = "telephoneNumber;lang-" + sLangTag;
        _sFax = "facsimileTelephoneNumber;lang-" + sLangTag;
        _sAddr = "registeredAddress;lang-" + sLangTag;
        _sAlias = "aliasedObjectName;lang-" + sLangTag;
        _sPhoneticOU = "ou;phonetic;lang-" + sLangTag;
        _sPhoneticAddr = "registeredAddress;phonetic;lang-" + sLangTag;
        _sHelp = sHelp;
        _isPhonetic = isPhonetic;
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
            if (argString.equalsIgnoreCase(_sOU)) {
                _tfName.setText(observable.get(_sOU, 0));
            } else if (argString.equalsIgnoreCase(_sDesc)) {
                _tfDescription.setText("");
                Vector vDesc = observable.get(_sDesc);
                Enumeration eDesc = vDesc.elements();
                if (eDesc.hasMoreElements()) {
                    _tfDescription.append((String) eDesc.nextElement());
                }
                while (eDesc.hasMoreElements()) {
                    _tfDescription.append("\n" + eDesc.nextElement());
                }
            } else if (argString.equalsIgnoreCase(_sPhone)) {
                _tfPhone.setText("");
                Vector vPhone = observable.get(_sPhone);
                Enumeration ePhone = vPhone.elements();
                if (ePhone.hasMoreElements()) {
                    _tfPhone.append((String) ePhone.nextElement());
                }
                while (ePhone.hasMoreElements()) {
                    _tfPhone.append("\n" + ePhone.nextElement());
                }
            } else if (argString.equalsIgnoreCase(_sFax)) {
                _tfFax.setText("");
                Vector vFax = observable.get(_sFax);
                Enumeration eFax = vFax.elements();
                if (eFax.hasMoreElements()) {
                    _tfFax.append((String) eFax.nextElement());
                }
                while (eFax.hasMoreElements()) {
                    _tfFax.append("\n" + eFax.nextElement());
                }
            } else if (argString.equalsIgnoreCase(_sAddr)) {
                _tfAddress.setText("");
                Vector vAddress = observable.get(_sAddr);
                Enumeration eAddress = vAddress.elements();
                if (eAddress.hasMoreElements()) {
                    _tfAddress.append((String) eAddress.nextElement());
                }
                while (eAddress.hasMoreElements()) {
                    _tfAddress.append("\n" + eAddress.nextElement());
                }
            } else if (argString.equalsIgnoreCase(_sAlias)) {
                _tfAlias.setText("");
                Vector vAlias = observable.get(_sAlias);
                Enumeration eAlias = vAlias.elements();
                if (eAlias.hasMoreElements()) {
                    _tfAlias.append((String) eAlias.nextElement());
                }
                while (eAlias.hasMoreElements()) {
                    _tfAlias.append("\n" + eAlias.nextElement());
                }
            } else if (argString.equalsIgnoreCase(_sPhoneticOU)) {
                _tfPhoneticName.setText(observable.get(_sPhoneticOU, 0));
            } else if (argString.equalsIgnoreCase(_sPhoneticAddr)) {
                _tfPhoneticAddress.setText("");
                Vector vAddress = observable.get(_sPhoneticAddr);
                Enumeration eAddress = vAddress.elements();
                if (eAddress.hasMoreElements()) {
                    _tfPhoneticAddress.append(
                            (String) eAddress.nextElement());
                }
                while (eAddress.hasMoreElements()) {
                    _tfPhoneticAddress.append("\n" +
                            eAddress.nextElement());
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
        JLabel lblName, lblDescription, lblPhone, lblFax, lblAlias, lblAddress;
        JLabel plblPronunciation, lblNameP, lblAddressP;

        PickerEditorResourceSet resource = new PickerEditorResourceSet();
        ID = resource.getString("userPage", _sLangTag);

        JPanel p = new JPanel(new GridBagLayout());

        lblName = new JLabel(resource.getString("OUPage", "nameNoStar"),
                JLabel.RIGHT);
        GridBagUtil.constrain(p, lblName, 0, row, 1, 1, 0.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.VERT_WINDOW_INSET,
                SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);

        _tfName = new JTextField();
        lblName.setLabelFor(_tfName);
        GridBagUtil.constrain(p, _tfName, 1, row,
                GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.VERT_WINDOW_INSET,
                SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0,
                SuiLookAndFeel.HORIZ_WINDOW_INSET);

        row++;

        lblDescription = new JLabel(resource.getString("OUPage", "description"),
                JLabel.RIGHT);
        GridBagUtil.constrain(p, lblDescription, 0, row, 1, 1, 0.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);

        _tfDescription = new UGTextArea();
        lblDescription.setLabelFor(_tfDescription);
        GridBagUtil.constrain(p, _tfDescription, 1, row,
                GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.BOTH,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0,
                SuiLookAndFeel.HORIZ_WINDOW_INSET);

        row++;

        lblPhone = new JLabel(resource.getString("OUPage", "phone"),
                JLabel.RIGHT);
        GridBagUtil.constrain(p, lblPhone, 0, row, 1, 1, 0.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);

        _tfPhone = new UGTextArea();
        lblPhone.setLabelFor(_tfPhone);
        GridBagUtil.constrain(p, _tfPhone, 1, row,
                GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.BOTH,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0,
                SuiLookAndFeel.HORIZ_WINDOW_INSET);

        row++;

        lblFax = new JLabel(resource.getString("OUPage", "fax"),
                JLabel.RIGHT);
        GridBagUtil.constrain(p, lblFax, 0, row, 1, 1, 0.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);

        _tfFax = new UGTextArea();
        
        GridBagUtil.constrain(p, _tfFax, 1, row,
                GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.BOTH,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0,
                SuiLookAndFeel.HORIZ_WINDOW_INSET);

        row++;

        lblAlias = new JLabel(resource.getString("OUPage", "alias"),
                JLabel.RIGHT);
        GridBagUtil.constrain(p, lblAlias, 0, row, 1, 1, 0.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);

        _tfAlias = new UGTextArea();
        GridBagUtil.constrain(p, _tfAlias, 1, row,
                GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.BOTH,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0,
                SuiLookAndFeel.HORIZ_WINDOW_INSET);

        row++;

        lblAddress = new JLabel(resource.getString("OUPage", "address"),
                JLabel.RIGHT);
        GridBagUtil.constrain(p, lblAddress, 0, row, 1, 1, 0.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);

        _tfAddress = new UGTextArea();
        GridBagUtil.constrain(p, _tfAddress, 1, row,
                GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.BOTH,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0,
                SuiLookAndFeel.HORIZ_WINDOW_INSET);

        row++;

        _oldName = observable.getValues(_sOU);
        _tfName.setText(_oldName);

        Vector vDesc = observable.get(_sDesc);
        Enumeration eDesc = vDesc.elements();
        if (eDesc.hasMoreElements()) {
            _tfDescription.append((String) eDesc.nextElement());
        }
        while (eDesc.hasMoreElements()) {
            _tfDescription.append("\n" + eDesc.nextElement());
        }

        Vector vPhone = observable.get(_sPhone);
        Enumeration ePhone = vPhone.elements();
        if (ePhone.hasMoreElements()) {
            _tfPhone.append((String) ePhone.nextElement());
        }
        while (ePhone.hasMoreElements()) {
            _tfPhone.append("\n" + ePhone.nextElement());
        }

        Vector vFax = observable.get(_sFax);
        Enumeration eFax = vFax.elements();
        if (eFax.hasMoreElements()) {
            _tfFax.append((String) eFax.nextElement());
        }
        while (eFax.hasMoreElements()) {
            _tfFax.append("\n" + eFax.nextElement());
        }

        Vector vAddress = observable.get(_sAddr);
        Enumeration eAddress = vAddress.elements();
        if (eAddress.hasMoreElements()) {
            _tfAddress.append((String) eAddress.nextElement());
        }
        while (eAddress.hasMoreElements()) {
            _tfAddress.append("\n" + eAddress.nextElement());
        }

        Vector vAlias = observable.get(_sAlias);
        Enumeration eAlias = vAlias.elements();
        if (eAlias.hasMoreElements()) {
            _tfAlias.append((String) eAlias.nextElement());
        }
        while (eAlias.hasMoreElements()) {
            _tfAlias.append("\n" + eAlias.nextElement());
        }

        _tfName.addFocusListener(_focusAdaptor);
        _tfDescription.addFocusListener(_focusAdaptor);
        _tfPhone.addFocusListener(_focusAdaptor);
        _tfFax.addFocusListener(_focusAdaptor);
        _tfAddress.addFocusListener(_focusAdaptor);
        _tfAlias.addFocusListener(_focusAdaptor);

        // phonetic
        if (_isPhonetic) {
            plblPronunciation = new JLabel(resource.getString("userPage", "phonetic"),
                    JLabel.LEFT);
            GridBagUtil.constrain(p, plblPronunciation, 1, row, 1, 1, 0.0, 0.0,
                    GridBagConstraints.NORTHWEST,
                    GridBagConstraints.HORIZONTAL,
                    SuiLookAndFeel.SEPARATED_COMPONENT_SPACE,
                    SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);

            row++;

            lblNameP = new JLabel(resource.getString("OUPage", "nameNoStar"),
                    JLabel.RIGHT);
            GridBagUtil.constrain(p, lblNameP, 0, row, 1, 1, 0.0, 0.0,
                    GridBagConstraints.NORTHWEST,
                    GridBagConstraints.HORIZONTAL,
                    SuiLookAndFeel.COMPONENT_SPACE,
                    SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);

            _tfPhoneticName = new JTextField();
            lblNameP.setLabelFor(_tfPhoneticName);
            GridBagUtil.constrain(p, _tfPhoneticName, 1, row,
                    GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                    GridBagConstraints.NORTHWEST,
                    GridBagConstraints.HORIZONTAL,
                    SuiLookAndFeel.COMPONENT_SPACE,
                    SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0,
                    SuiLookAndFeel.HORIZ_WINDOW_INSET);

            row++;

            lblAddressP = new JLabel(resource.getString("OUPage", "address"),
                    JLabel.RIGHT);
            GridBagUtil.constrain(p, lblAddressP, 0, row, 1, 1, 0.0, 0.0,
                    GridBagConstraints.NORTHWEST,
                    GridBagConstraints.HORIZONTAL,
                    SuiLookAndFeel.COMPONENT_SPACE,
                    SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);

            _tfPhoneticAddress = new UGTextArea();
            lblAddressP.setLabelFor(_tfPhoneticAddress);
            GridBagUtil.constrain(p, _tfPhoneticAddress, 1, row,
                                  GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                                  GridBagConstraints.NORTHWEST, GridBagConstraints.BOTH,
                                  SuiLookAndFeel.COMPONENT_SPACE,
                                  SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0,
                                  SuiLookAndFeel.HORIZ_WINDOW_INSET);
            
            row++;

            _oldPhoneticName = observable.getValues(_sPhoneticOU);
            _tfPhoneticName.setText(_oldPhoneticName);

            Vector vPAddr = observable.get(_sPhoneticAddr);
            Enumeration ePAddr = vPAddr.elements();
            if (ePAddr.hasMoreElements()) {
                _tfPhoneticAddress.append((String) ePAddr.nextElement());
            }
            while (ePAddr.hasMoreElements()) {
                _tfPhoneticAddress.append("\n" + ePAddr.nextElement());
            }

            _tfPhoneticName.addFocusListener(_focusAdaptor);
            _tfPhoneticAddress.addFocusListener(_focusAdaptor);
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
        return _resource.getString("OUPage",_sLangTag);
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

        Vector vTmp = new Vector();
        vTmp.removeAllElements();
        StringTokenizer st = new StringTokenizer(_tfAlias.getText(), "\n\r");
        while (st.hasMoreTokens()) {
            vTmp.addElement(st.nextElement());
        }
        if (vTmp.size() != 0) {
            boolean fContain = false;

            Vector vOC = observable.get("ObjectClass");
            Enumeration eOC = vOC.elements();
            while (eOC.hasMoreElements()) {
                String sOC = (String) eOC.nextElement();
                if (sOC.equalsIgnoreCase(_aliasObjectClass)) {
                    fContain = true;
                    break;
                }
            }

            if (!fContain) {
                vOC.addElement(_aliasObjectClass);
                observable.replace("ObjectClass", vOC);
            }
            observable.replace(_sAlias, vTmp);
        } else {
            observable.delete(_sAlias);
        }

        if (!(_tfName.getText().equals(_oldName))) {
            if (_tfName.getText().equals("")) {
                observable.delete(_sOU, _oldName);
                _oldName = "";
            } else {
                observable.replace(_sOU, _tfName.getText());
                _oldName = _tfName.getText();
            }
        }

        vTmp.removeAllElements();
        st = new StringTokenizer(_tfDescription.getText(), "\n\r");
        while (st.hasMoreTokens()) {
            vTmp.addElement(st.nextElement());
        }
        if (vTmp.size() == 0) {
            observable.delete(_sDesc);
        } else {
            observable.replace(_sDesc, vTmp);
        }

        vTmp.removeAllElements();
        st = new StringTokenizer(_tfPhone.getText(), "\n\r");
        while (st.hasMoreTokens()) {
            vTmp.addElement(st.nextElement());
        }
        if (vTmp.size() == 0) {
            observable.delete(_sPhone);
        } else {
            observable.replace(_sPhone, vTmp);
        }

        vTmp.removeAllElements();
        st = new StringTokenizer(_tfFax.getText(), "\n\r");
        while (st.hasMoreTokens()) {
            vTmp.addElement(st.nextElement());
        }
        if (vTmp.size() == 0) {
            observable.delete(_sFax);
        } else {
            observable.replace(_sFax, vTmp);
        }

        vTmp.removeAllElements();
        st = new StringTokenizer(_tfAddress.getText(), "\n\r");
        while (st.hasMoreTokens()) {
            vTmp.addElement(st.nextElement());
        }
        if (vTmp.size() == 0) {
            observable.delete(_sAddr);
        } else {
            observable.replace(_sAddr, vTmp);
        }

        if (_isPhonetic &&
                !(_tfPhoneticName.getText().equals(_oldPhoneticName))) {
            if (_tfPhoneticName.getText().equals("")) {
                observable.delete(_sPhoneticOU, _oldPhoneticName);
                _oldPhoneticName = "";
            } else {
                observable.replace(_sPhoneticOU, _tfPhoneticName.getText());
                _oldPhoneticName = _tfPhoneticName.getText();
            }
        }

        if (_isPhonetic) {
            vTmp.removeAllElements();
            st = new StringTokenizer(_tfPhoneticAddress.getText(), "\n\r");
            while (st.hasMoreTokens()) {
                vTmp.addElement(st.nextElement());
            }
            if (vTmp.size() == 0) {
                observable.delete(_sPhoneticAddr);
            } else {
                observable.replace(_sPhoneticAddr, vTmp);
            }
        }
        return fReturn;

    }

    /**
     * Implements the IResourceEditorPage interface.
      * Clears all information on the page.
     */
    public void clear() {
        _tfName.setText("");
        _tfPhone.setText("");
        _tfFax.setText("");
        _tfDescription.setText("");
        _tfAddress.setText("");
        _tfAlias.setText("");
        if (_isPhonetic) {
            _tfPhoneticName.setText("");
            _tfPhoneticAddress.setText("");
        }
    }

    /**
     * Implements the IResourceEditorPage interface.
      * Resets information on the page.
     */
    public void reset() {
        _tfName.setText(_oldName);
        if (_isPhonetic) {
            _tfPhoneticName.setText(_oldPhoneticName);
        }
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
     * Implements the IResourceEditorPage interface.
      * Displays help information for the page
     */
    public void help() {
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

    /**
      * set the localize state.
      *
      * @param fLocalize true if the page is localized. false otherwise.
      */
    public void setLocalize(boolean fLocalize) {
        _fLocalize = fLocalize;
    }
}
