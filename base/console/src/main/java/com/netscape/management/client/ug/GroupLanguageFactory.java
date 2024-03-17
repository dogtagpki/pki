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
 * GroupLanguageFactory generates language pages for the group resource editor.
 *
 * @see LanguagePage
 * @see ILanguageFactory
 */
class GroupLanguageFactory implements ILanguageFactory {

    PickerEditorResourceSet _resource = new PickerEditorResourceSet();
    int iCount = Integer.parseInt(_resource.getString("GroupPage","pluginCount"));
    ResEditorGroupPageGeneralLang[] langs;


    /**
     * Constructor. Creates as many language pages as specified in the property file.
     */
    public GroupLanguageFactory() {
        langs = new ResEditorGroupPageGeneralLang[iCount];
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
    public IResourceEditorPage getPage(String language) {
        for (int i = 0; i < iCount; i++) {
            if (language.equals(
                                _resource.getString("GroupPage", "plugin"+i))) {
                if (langs[i] == null) {
                    String sPhonetic =
                        _resource.getString("GroupPage","phonetic"+i);
                    if (sPhonetic.equalsIgnoreCase("true"))
                        langs[i] = new ResEditorGroupPageGeneralLang(
                                                                     _resource.getString("GroupPage",
                                                                                         "plugin"+i), "ResEditorGroupPageLangWP",
                                                                     true);
                    else
                        langs[i] = new ResEditorGroupPageGeneralLang(
                                                                     _resource.getString("GroupPage",
                                                                                         "plugin"+i), "ResEditorGroupPageLang",
                                                                     false);
                }
                return langs[i];
            }
        }
        return null;
    }
}


/**
  * ResEditorGroupPageGeneralLang is the IResourceEditorPage that the
  * GroupLanguageFactory generates. Phonetic fields are created depending
  * on the language.
  */
class ResEditorGroupPageGeneralLang extends JPanel implements IResourceEditorPage,
                                                              Observer, ILocalize {
    PickerEditorResourceSet _resource = new PickerEditorResourceSet();

    private String ID;

    JTextField _groupName;
    JTextArea _groupDescription;
    JTextField _phoneticGroupName;

    boolean _isModified = false;
    boolean _isReadOnly = false;
    boolean _isEnable = true;
    boolean _isPhonetic = false;

    String _oldGroupName, _oldPhoneticGroupName;

    String _sIndex;
    String _sDesc;
    String _sLangTag;
    String _sPhoneticIndex;
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
                                                                      ResEditorGroupPageGeneralLang.this);
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
                } else if (src == _phoneticGroupName) {
                    _observable.replace(_sPhoneticIndex,
                                        _phoneticGroupName.getText());
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
    public ResEditorGroupPageGeneralLang(String sLangTag, String sHelp,
                                         boolean isPhonetic) {
        super(true);

        _sLangTag = sLangTag;
        _sIndex = "cn;lang-" + sLangTag;
        _sDesc = "description;lang-" + sLangTag;
        _sPhoneticIndex = "cn;phonetic;lang-" + sLangTag;
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
            } else if (argString.equalsIgnoreCase(_sPhoneticIndex)) {
                _phoneticGroupName.setText(
                                           observable.get(_sPhoneticIndex, 0));
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
        JLabel lblName, lblDescription, lblPhonetic, lblNamePhonetic;

        PickerEditorResourceSet resource = new PickerEditorResourceSet();
        ID = resource.getString("userPage", _sLangTag);

        JPanel p = new JPanel(new GridBagLayout());
        lblName =
            new JLabel(resource.getString("groupInfoPage", "nameNoStar"),
                       JLabel.RIGHT);
        GridBagUtil.constrain(p, lblName, 0, row, 1, 1, 0.0, 0.0,
                              GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                              SuiLookAndFeel.VERT_WINDOW_INSET,
                              SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);

        _groupName = new JTextField();
        lblName.setLabelFor(_groupName);
        GridBagUtil.constrain(p, _groupName, 1, row,
                              GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                              GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                              SuiLookAndFeel.VERT_WINDOW_INSET,
                              SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0,
                              SuiLookAndFeel.HORIZ_WINDOW_INSET);

        row++;

        lblDescription =
            new JLabel(resource.getString("groupInfoPage", "description"),
                       JLabel.RIGHT);
        GridBagUtil.constrain(p, lblDescription, 0, row, 1, 1, 0.0, 0.0,
                              GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                              SuiLookAndFeel.COMPONENT_SPACE,
                              SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);

        _groupDescription = new UGTextArea();
        lblDescription.setLabelFor(_groupDescription);
        GridBagUtil.constrain(p, _groupDescription, 1, row,
                              GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                              GridBagConstraints.NORTHWEST, GridBagConstraints.BOTH,
                              SuiLookAndFeel.COMPONENT_SPACE,
                              SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0,
                              SuiLookAndFeel.HORIZ_WINDOW_INSET);

        row++;

        _oldGroupName = observable.getValues(_sIndex);
        _groupName.setText(_oldGroupName);

        Vector vDesc = observable.get(_sDesc);
        Enumeration eDesc = vDesc.elements();
        if (eDesc.hasMoreElements()) {
            _groupDescription.append((String) eDesc.nextElement());
        }
        while (eDesc.hasMoreElements()) {
            _groupDescription.append("\n" + eDesc.nextElement());
        }

        _groupName.addFocusListener(_focusAdaptor);
        _groupDescription.addFocusListener(_focusAdaptor);

        if (_isPhonetic) {
            lblPhonetic = new JLabel(resource.getString("userPage", "phonetic"),
                                     JLabel.LEFT);
            GridBagUtil.constrain(p, lblPhonetic, 1, row, 1, 1, 0.0, 0.0,
                                  GridBagConstraints.NORTHWEST,
                                  GridBagConstraints.HORIZONTAL,
                                  SuiLookAndFeel.SEPARATED_COMPONENT_SPACE,
                                  SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);

            row++;

            lblNamePhonetic =
                new JLabel(resource.getString("groupInfoPage", "nameNoStar"),
                           JLabel.RIGHT);
            GridBagUtil.constrain(p, lblNamePhonetic, 0, row, 1, 1, 0.0, 0.0,
                                  GridBagConstraints.NORTHWEST,
                                  GridBagConstraints.HORIZONTAL,
                                  SuiLookAndFeel.COMPONENT_SPACE,
                                  SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);

            _phoneticGroupName = new JTextField();
            lblNamePhonetic.setLabelFor(_phoneticGroupName);
            GridBagUtil.constrain(p, _phoneticGroupName, 1, row,
                                  GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                                  GridBagConstraints.NORTHWEST,
                                  GridBagConstraints.HORIZONTAL,
                                  SuiLookAndFeel.COMPONENT_SPACE,
                                  SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0,
                                  SuiLookAndFeel.HORIZ_WINDOW_INSET);

            row++;

            _oldPhoneticGroupName = observable.getValues(_sPhoneticIndex);
            _phoneticGroupName.setText(_oldPhoneticGroupName);
            _phoneticGroupName.addFocusListener(_focusAdaptor);
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
        return _resource.getString("userPage",_sLangTag);
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

        if (!(_groupName.getText().equals(_oldGroupName))) {
            if (_groupName.getText().equals("")) {
                observable.delete(_sIndex, _oldGroupName);
                _oldGroupName = "";
            } else {
                observable.replace(_sIndex, _groupName.getText());
                _oldGroupName = _groupName.getText();
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

        if (_isPhonetic && !(_phoneticGroupName.getText().equals(
                                                                 _oldPhoneticGroupName))) {
            if (_phoneticGroupName.getText().equals("")) {
                observable.delete(_sPhoneticIndex, _oldPhoneticGroupName);
                _oldPhoneticGroupName = "";
            } else {
                observable.replace(_sPhoneticIndex,
                                   _phoneticGroupName.getText());
                _oldPhoneticGroupName = _phoneticGroupName.getText();
            }
        }

        return fReturn;
    }


    /**
     * Implements the IResourceEditorPage interface.
     * Clears all information on the page.
     */
    public void clear() {
        _groupName.setText("");
        _groupDescription.setText("");
        if (_isPhonetic)
            _phoneticGroupName.setText("");
    }


    /**
     * Implements the IResourceEditorPage interface.
     * Resets information on the page.
     */
    public void reset() {
        _groupName.setText(_oldGroupName);
        if (_isPhonetic)
            _phoneticGroupName.setText(_oldPhoneticGroupName);
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
    ;

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
