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
 * ResEditorPosixUser is a plugin for the ResourceEditor. It is used
 * when editing Posix user information.
 *
 * @see IResourceEditorPage
 * @see ResourceEditor
 */

public class ResEditorPosixUser extends JPanel implements IResourceEditorPage,
Observer {
    public static String _POSIXOBJECTCLASS="posixAccount";
    public static String _UIDNUMBER="uidnumber";
    public static String _GIDNUMBER="gidnumber";
    public static String _HOMEDIRECTORY="homedirectory";
    public static String _LOGINSHELL="loginshell";
    public static String _GECOS="gecos";
    
    PickerEditorResourceSet _resource = new PickerEditorResourceSet();
    private String ID;

    boolean    _enableModified; // A flag if _cbEnable was modified
    
    JCheckBox  _cbEnable;
    JTextField _tfUIDNumber;
    JTextField _tfGIDNumber;
    JTextField _tfHomeDirectory;
    JTextField _tfLoginShell;
    JTextField _tfGecos;
    
    String _oldUIDNumber;
    String _oldGIDNumber;
    String _oldHomeDirectory;
    String _oldLoginShell;
    String _oldGecos;
    
    boolean _isModified = false;
    boolean _isReadOnly = false;
    boolean _isEnable = true;
    
    ResourceEditor _resourceEditor;
    
    ConsoleInfo _info;
    
    ResourcePageObservable _observable;
    private Vector componentVector = new Vector();
    
    /**
     * Used to notify the ResourcePageObservable when a value has changed.
     * Note that this updates all observers.
     */
    FocusAdapter _focusAdaptor = new FocusAdapter() {
        public void focusLost(FocusEvent e) {
 
            // 550649 Chinese locale: If a focus is lost because the
            // window is no more active, do not update observable. Do it
            // only when another components in the same window gets focus.
            Window w = (Window) SwingUtilities.getAncestorOfClass(Window.class, ResEditorPosixUser.this);
            if(w != null && w.getFocusOwner() == null) {
                return;
            }
 
            if (_observable == null) {
                return;
            }
            Component src = e.getComponent();
            if (src == _tfUIDNumber) {
                _observable.replace(_UIDNUMBER, _tfUIDNumber.getText());
            } else if (src==_tfGIDNumber)
            {
                _observable.replace(_GIDNUMBER, _tfGIDNumber.getText());
            } else if (src==_tfHomeDirectory)
            {
                _observable.replace(_HOMEDIRECTORY, _tfHomeDirectory.getText());
            } else if (src==_tfLoginShell)
            {
                _observable.replace(_LOGINSHELL, _tfLoginShell.getText());
            } else if (src==_tfGecos)
            {
                _observable.replace(_GECOS, _tfGecos.getText());
            }
        }
    };
    
    ActionListener enableActionListener = new ActionListener()
        {
            public void actionPerformed(ActionEvent ev)
            {
                _enableModified = true;

                boolean state = _cbEnable.isSelected();
                Enumeration e = componentVector.elements();
                while(e.hasMoreElements())
                {
                    JComponent c = (JComponent)e.nextElement();
                    c.setEnabled(state);
                }
            }
        };
    
    /**
     * Constructor
     */
    public ResEditorPosixUser() {
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
        ID = _resource.getString("Posix", "ID");
        _resourceEditor = parent;
        _observable = observable;
        _info = observable.getConsoleInfo();
        
        JLabel infoLabel = new JLabel(_resource.getString("userPage","required"));
        JLabel jlUIDNumber = new JLabel( _resource.getString("Posix", "uidNumber"), SwingConstants.RIGHT);
        JLabel jlGIDNumber = new JLabel( _resource.getString("Posix", "gidNumber"), SwingConstants.RIGHT);
        JLabel jlHomeDirectory = new JLabel( _resource.getString("Posix", "homeDirectory"), SwingConstants.RIGHT);
        JLabel jlLoginShell = new JLabel( _resource.getString("Posix", "loginShell"), SwingConstants.RIGHT);
        JLabel jlGecos = new JLabel( _resource.getString("Posix", "Gecos"), SwingConstants.RIGHT);
        JLabel blankLabel = new JLabel(""); // Prevents components of this panel from centering
        componentVector.addElement(infoLabel);
        componentVector.addElement(jlUIDNumber);
        componentVector.addElement(jlGIDNumber);
        componentVector.addElement(jlHomeDirectory);
        componentVector.addElement(jlLoginShell);
        componentVector.addElement(jlGecos);
        
        _cbEnable = new JCheckBox(_resource.getString("Posix","enable"));
        _tfUIDNumber = new JTextField();
        jlUIDNumber.setLabelFor(_tfUIDNumber);
        _tfGIDNumber = new JTextField();
        jlGIDNumber.setLabelFor(_tfGIDNumber);
        _tfHomeDirectory = new JTextField();
        jlHomeDirectory.setLabelFor(_tfHomeDirectory);
        _tfLoginShell = new JTextField();
        jlLoginShell.setLabelFor(_tfLoginShell);
        _tfGecos = new JTextField();
        jlGecos.setLabelFor(_tfGecos);
        componentVector.addElement(_tfUIDNumber);
        componentVector.addElement(_tfGIDNumber);
        componentVector.addElement(_tfHomeDirectory);
        componentVector.addElement(_tfLoginShell);
        componentVector.addElement(_tfGecos);
        
        _cbEnable.addActionListener(enableActionListener);
        _tfUIDNumber.addFocusListener(_focusAdaptor);
        _tfGIDNumber.addFocusListener(_focusAdaptor);
        _tfHomeDirectory.addFocusListener(_focusAdaptor);
        _tfLoginShell.addFocusListener(_focusAdaptor);
        _tfGecos.addFocusListener(_focusAdaptor);
        
        JPanel p = new JPanel(new GridBagLayout());
        
        GridBagUtil.constrain(p, _cbEnable, 0, 0, GridBagConstraints.REMAINDER, 1, 0.0,
                              0.0, GridBagConstraints.NORTHWEST,
                              GridBagConstraints.HORIZONTAL,
                              SuiLookAndFeel.VERT_WINDOW_INSET,
                              SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);
        
        GridBagUtil.constrain(p, jlUIDNumber, 0, 1, 1, 1, 0.0, 0.0,
                              GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                              SuiLookAndFeel.VERT_WINDOW_INSET,
                              SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);
        GridBagUtil.constrain(p, _tfUIDNumber, 1, 1,
                              GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                              GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                              SuiLookAndFeel.VERT_WINDOW_INSET,
                              SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0,
                              SuiLookAndFeel.HORIZ_WINDOW_INSET);
        GridBagUtil.constrain(p, jlGIDNumber, 0, 2, 1, 1, 0.0, 0.0,
                              GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                              SuiLookAndFeel.VERT_WINDOW_INSET,
                              SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);
        GridBagUtil.constrain(p, _tfGIDNumber, 1, 2,
                              GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                              GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                              SuiLookAndFeel.VERT_WINDOW_INSET,
                              SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0,
                              SuiLookAndFeel.HORIZ_WINDOW_INSET);
        GridBagUtil.constrain(p, jlHomeDirectory, 0, 3, 1, 1, 0.0, 0.0,
                              GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                              SuiLookAndFeel.VERT_WINDOW_INSET,
                              SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);
        GridBagUtil.constrain(p, _tfHomeDirectory, 1, 3,
                              GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                              GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                              SuiLookAndFeel.VERT_WINDOW_INSET,
                              SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0,
                              SuiLookAndFeel.HORIZ_WINDOW_INSET);
        GridBagUtil.constrain(p, jlLoginShell, 0, 4, 1, 1, 0.0, 0.0,
                              GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                              SuiLookAndFeel.VERT_WINDOW_INSET,
                              SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);
        GridBagUtil.constrain(p, _tfLoginShell, 1, 4,
                              GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                              GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                              SuiLookAndFeel.VERT_WINDOW_INSET,
                              SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0,
                              SuiLookAndFeel.HORIZ_WINDOW_INSET);
        GridBagUtil.constrain(p, jlGecos, 0, 5, 1, 1, 0.0, 0.0,
                              GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                              SuiLookAndFeel.VERT_WINDOW_INSET,
                              SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);
        GridBagUtil.constrain(p, _tfGecos, 1, 5,
                              GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                              GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                              SuiLookAndFeel.VERT_WINDOW_INSET,
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
        
        // set up the value
        Vector valueVector = observable.get("objectclass");
        _cbEnable.setSelected(!valueVector.contains(_POSIXOBJECTCLASS));
        _cbEnable.doClick();
        _enableModified = false;
            
        _oldUIDNumber = observable.get(_UIDNUMBER, 0);
        _tfUIDNumber.setText(_oldUIDNumber);
        _oldGIDNumber = observable.get(_GIDNUMBER, 0);
        _tfGIDNumber.setText(_oldGIDNumber);
        _oldHomeDirectory = observable.get(_HOMEDIRECTORY, 0);
        _tfHomeDirectory.setText(_oldHomeDirectory);
        _oldLoginShell = observable.get(_LOGINSHELL, 0);
        _tfLoginShell.setText(_oldLoginShell);
        _oldGecos = observable.get(_GECOS, 0);
        _tfGecos.setText(_oldGecos);
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
            if (argString.equalsIgnoreCase(_UIDNUMBER)) {
                _tfUIDNumber.setText(observable.get(_UIDNUMBER, 0));
            } else if (argString.equalsIgnoreCase(_GIDNUMBER)) {
                _tfGIDNumber.setText(observable.get(_GIDNUMBER, 0));
            } else if (argString.equalsIgnoreCase(_HOMEDIRECTORY)) {
                _tfHomeDirectory.setText(observable.get(_HOMEDIRECTORY, 0));
            } else if (argString.equalsIgnoreCase(_LOGINSHELL)) {
                _tfLoginShell.setText(observable.get(_LOGINSHELL, 0));
            } else if (argString.equalsIgnoreCase(_GECOS)) {
                _tfGecos.setText(observable.get(_GECOS, 0));
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
        
        if (!_enableModified) {
            ; //  no changes for _cbEnable
        }
        else if(_cbEnable.isSelected())
        {
            Vector valueVector = observable.get("objectclass");
            if(!valueVector.contains(_POSIXOBJECTCLASS))
                valueVector.addElement(_POSIXOBJECTCLASS);
            observable.replace("objectclass", valueVector);
        }
        else
        {
            Vector valueVector = observable.get("objectclass");
            if(valueVector.contains(_POSIXOBJECTCLASS))
                valueVector.removeElement(_POSIXOBJECTCLASS);
            observable.replace("objectclass", valueVector);
            
            observable.delete(_UIDNUMBER, "");
            observable.delete(_GIDNUMBER, "");
            observable.delete(_HOMEDIRECTORY, "");
            observable.delete(_LOGINSHELL, "");
            observable.delete(_GECOS, "");
            return true;
        }
        
        String sUIDNumber=_tfUIDNumber.getText();
        if (sUIDNumber.equals(_oldUIDNumber)==false)
        {
            observable.replace(_UIDNUMBER,sUIDNumber);
        }
        String sGIDNumber=_tfGIDNumber.getText();
        if (sGIDNumber.equals(_oldGIDNumber)==false)
        {
            observable.replace(_GIDNUMBER,sGIDNumber);
        }
        String sHomeDirectory=_tfHomeDirectory.getText();
        if (sHomeDirectory.equals(_oldHomeDirectory)==false)
        {
            observable.replace(_HOMEDIRECTORY,sHomeDirectory);
        }
        String sLoginShell=_tfLoginShell.getText();
        if (sLoginShell.equals(_oldLoginShell)==false)
        {
            observable.replace(_LOGINSHELL,sLoginShell);
        }
        String sGecos=_tfGecos.getText();
        if (sGecos.equals(_oldGecos)==false)
        {
            observable.replace(_GECOS,sGecos);
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
        /*
        _groupName.setText("");
           _groupDescription.setText("");
         */
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
        if (_cbEnable.isSelected()) {
            if ((_tfUIDNumber.getText().trim().length() == 0)||(_tfGIDNumber.getText().trim().length()==0)) {
                SuiOptionPane.showMessageDialog(null,
                        _resource.getString("resourceEditor", "IncompleteText"),
                        _resource.getString("resourceEditor",
                        "IncompleteTitle"), SuiOptionPane.ERROR_MESSAGE);
                ModalDialogUtil.sleep();
                return false;
            }
            int testval;
            try {
                testval = Integer.parseInt(_tfUIDNumber.getText().trim());
            } catch (NumberFormatException nfe) {
                SuiOptionPane.showMessageDialog(null,
                        _resource.getString("resourceEditor", "UidNotANumberText"),
                        _resource.getString("resourceEditor",
                        "UidNotANumberTitle"), SuiOptionPane.ERROR_MESSAGE);
                ModalDialogUtil.sleep();
                return false;
            }
            if (testval < 0) {
                SuiOptionPane.showMessageDialog(null,
                        _resource.getString("resourceEditor", "UidNotValidText"),
                        _resource.getString("resourceEditor",
                        "UidNotValidTitle"), SuiOptionPane.ERROR_MESSAGE);
                ModalDialogUtil.sleep();
                return false;                
            }
            if (testval == 0) {
                Object[] val1 = {_resource.getString("resourceEditor", "yesButton"),
                        _resource.getString("resourceEditor", "noButton")};
                Object[] msg1 = {_resource.getString("resourceEditor", "errorText1"),
                        _resource.getString("resourceEditor", "errorText2"),
                        _resource.getString("resourceEditor", "errorText3")};
                int selection = SuiOptionPane.showOptionDialog(null, msg1,
                        _resource.getString("resourceEditor", "errorTitle"),
                        SuiOptionPane.DEFAULT_OPTION,
                        SuiOptionPane.WARNING_MESSAGE, null, val1, val1[0]);

                if (selection == 1) {
                    ModalDialogUtil.sleep();
                    return false;
                }
            }
            try {
                testval = Integer.parseInt(_tfGIDNumber.getText().trim());
            } catch (NumberFormatException nfe) {
                SuiOptionPane.showMessageDialog(null,
                        _resource.getString("resourceEditor", "GidNotANumberText"),
                        _resource.getString("resourceEditor",
                        "GidNotANumberTitle"), SuiOptionPane.ERROR_MESSAGE);
                ModalDialogUtil.sleep();
                return false;
            }
            if (testval < 0) {
                SuiOptionPane.showMessageDialog(null,
                        _resource.getString("resourceEditor", "GidNotValidText"),
                        _resource.getString("resourceEditor",
                        "GidNotValidTitle"), SuiOptionPane.ERROR_MESSAGE);
                ModalDialogUtil.sleep();
                return false;                
            }
            if (testval == 0) {
                Object[] val1 = {_resource.getString("resourceEditor", "yesButton"),
                        _resource.getString("resourceEditor", "noButton")};
                Object[] msg1 = {_resource.getString("resourceEditor", "errorText1"),
                        _resource.getString("resourceEditor", "errorText2"),
                        _resource.getString("resourceEditor", "errorText3")};
                int selection = SuiOptionPane.showOptionDialog(null, msg1,
                        _resource.getString("resourceEditor", "errorTitle"),
                        SuiOptionPane.DEFAULT_OPTION,
                        SuiOptionPane.WARNING_MESSAGE, null, val1, val1[0]);

                if (selection == 1) {
                    ModalDialogUtil.sleep();
                    return false;
                }
            }
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
        
        help.contextHelp("ug","ResEditorPosixUser");
    }
}
