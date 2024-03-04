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
import com.netscape.management.nmclf.*;

import javax.swing.*;


/**
 * OUPage is a plugin for the ResourceEditor. It is used when editing
 * the organizational unit information.
 *
 * @see IResourceEditorPage
 * @see ResourceEditor
 *
 */
public class OUPage extends JPanel implements IResourceEditorPage,
Observer {
    PickerEditorResourceSet _resource = new PickerEditorResourceSet();

    private String ID;

    JTextField _tfName;
    JTextArea _tfDescription;
    JTextArea _tfPhone;
    JTextArea _tfFax;
    JTextArea _tfAddress;
    JTextArea _tfAlias;

    boolean _isModified = false;
    boolean _isReadOnly = false;
    boolean _isEnable = true;
    boolean _createNewUser;

    String _oldName;

    String _sOU;
    String _sDesc;
    String _sPhone;
    String _sFax;
    String _sAddr;
    String _sAlias;

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
                    Window w = (Window) SwingUtilities.getAncestorOfClass(Window.class, OUPage.this);
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
                    }
                }
            };


    /**
    * Constructor
    */
    public OUPage() {
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

        _sOU = "ou";
        _sDesc = "description";
        _sPhone = "telephoneNumber";
        _sFax = "facsimileTelephoneNumber";
        _sAddr = "registeredAddress";
        _sAlias = "aliasedObjectName";

        _createNewUser = observable.isNewUser();
        observable.setIndexAttribute("ou");
        
        ID = _resource.getString("OUPage","ID");

        JLabel infoLabel = new JLabel(_resource.getString("userPage","required"));
        JLabel nameLabel = new JLabel(_resource.getString("OUPage", "name"),
                SwingConstants.RIGHT);
        JLabel descriptionLabel = new JLabel(
                _resource.getString("OUPage", "description"),
                SwingConstants.RIGHT);
        JLabel phoneLabel =
                new JLabel(_resource.getString("OUPage", "phone"),
                SwingConstants.RIGHT);
        JLabel faxLabel = new JLabel(_resource.getString("OUPage", "fax"),
                SwingConstants.RIGHT);
        JLabel aliasLabel =
                new JLabel(_resource.getString("OUPage", "alias"),
                SwingConstants.RIGHT);
        JLabel addressLabel =
                new JLabel(_resource.getString("OUPage", "address"),
                SwingConstants.RIGHT);
        JLabel blankLabel = new JLabel(""); // Prevents components of this panel from centering

        _tfName = new JTextField();
        nameLabel.setLabelFor(_tfName);
        _tfDescription = new UGTextArea();
        descriptionLabel.setLabelFor(_tfDescription);
        _tfPhone = new UGTextArea();
        phoneLabel.setLabelFor(_tfPhone);
        _tfFax = new UGTextArea();
        faxLabel.setLabelFor(_tfFax);
        _tfAlias = new UGTextArea();
        aliasLabel.setLabelFor(_tfAlias);
        _tfAddress = new UGTextArea();
        addressLabel.setLabelFor(_tfAddress);

        _tfName.addFocusListener(_focusAdaptor);
        _tfDescription.addFocusListener(_focusAdaptor);
        _tfPhone.addFocusListener(_focusAdaptor);
        _tfFax.addFocusListener(_focusAdaptor);
        _tfAlias.addFocusListener(_focusAdaptor);
        _tfAddress.addFocusListener(_focusAdaptor);

        JPanel p = new JPanel(new GridBagLayout());
        GridBagUtil.constrain(p, nameLabel, 0, 0, 1, 1, 0.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.VERT_WINDOW_INSET,
                SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);
        GridBagUtil.constrain(p, _tfName, 1, 0,
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
        GridBagUtil.constrain(p, _tfDescription, 1, 1,
                GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.BOTH,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0,
                SuiLookAndFeel.HORIZ_WINDOW_INSET);

        GridBagUtil.constrain(p, phoneLabel, 0, 2, 1, 1, 0.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);
        GridBagUtil.constrain(p, _tfPhone, 1, 2,
                GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.BOTH,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0,
                SuiLookAndFeel.HORIZ_WINDOW_INSET);

        GridBagUtil.constrain(p, faxLabel, 0, 3, 1, 1, 0.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);
        GridBagUtil.constrain(p, _tfFax, 1, 3,
                GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.BOTH,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0,
                SuiLookAndFeel.HORIZ_WINDOW_INSET);

        GridBagUtil.constrain(p, aliasLabel, 0, 4, 1, 1, 0.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);
        GridBagUtil.constrain(p, _tfAlias, 1, 4,
                GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.BOTH,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0,
                SuiLookAndFeel.HORIZ_WINDOW_INSET);

        GridBagUtil.constrain(p, addressLabel, 0, 5, 1, 1, 0.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);
        GridBagUtil.constrain(p, _tfAddress, 1, 5,
                GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.BOTH,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0,
                SuiLookAndFeel.HORIZ_WINDOW_INSET);

        GridBagUtil.constrain(p, infoLabel, 1, 6,
                GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.VERT_WINDOW_INSET,
                SuiLookAndFeel.HORIZ_WINDOW_INSET, 0,
                SuiLookAndFeel.HORIZ_WINDOW_INSET);

        GridBagUtil.constrain(p, blankLabel, 0, 7,
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

        // Initialize fields
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
            Vector vOC = observable.get("ObjectClass");
            vOC.removeElement(_aliasObjectClass);
            observable.replace("ObjectClass", vOC);
            observable.delete(_sAlias);
        }

        if (_tfName.getText().equals(_oldName) == false) {
            if (_tfName.getText().trim().length() == 0) {
                observable.delete(_sOU, _oldName);
                _oldName = "";
            } else {
                String newName = _tfName.getText().trim();
                observable.replace(_sOU, newName);
                _oldName = newName;
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
    }

    /**
     * Implements the IResourceEditorPage interface.
      * Resets information on the page.
     */
    public void reset() {
        _tfName.setText(_oldName);
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
        if (_tfName.getText().trim().length() == 0) {
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

        help.contextHelp("ug","OUPageDef");
    }
}

