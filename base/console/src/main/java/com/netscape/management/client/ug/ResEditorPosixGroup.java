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

import java.util.*;
import java.awt.*;
import java.awt.event.*;

import javax.swing.*;
import com.netscape.management.client.console.*;
import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;


/**
 * ResEditorPosixGroup is a plugin for the ResourceEditor. It is used
 * when editing Posix group information.
 *
 * @see IResourceEditorPage
 * @see ResourceEditor
 */

public class ResEditorPosixGroup extends JPanel implements IResourceEditorPage,
Observer {
    public static String _POSIXOBJECTCLASS="posixgroup";
    public static String _GIDNUMBER="gidnumber";
    public static String _MEMBERUID="memberuid";
   
    PickerEditorResourceSet _resource = new PickerEditorResourceSet();
    private String ID;

    boolean    _enableModified; // A flag if _cbEnable was modified
    
    JCheckBox  _cbEnable;
    JTextField _tfGIDNumber;
    
    String _oldGIDNumber;
     
    boolean _isModified = false;
    boolean _isReadOnly = false;
    boolean _isEnable = true;
    
    ResourceEditor _resourceEditor;
    ResEditorPosixGpMembers posixGroup;
    
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
            Window w = (Window) SwingUtilities.getAncestorOfClass(Window.class, ResEditorPosixGroup.this);
            if(w != null && w.getFocusOwner() == null) {
                return;
            }
 
            if (_observable == null) {
                return;
            }
            Component src = e.getComponent();
            if (src==_tfGIDNumber)
            {
                _observable.replace(_GIDNUMBER, _tfGIDNumber.getText());
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
    public ResEditorPosixGroup() {
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
        ID = _resource.getString("PosixGroup", "ID");
        _resourceEditor = parent;
        _observable = observable;
        _info = observable.getConsoleInfo();
        posixGroup = new ResEditorPosixGpMembers(
                _resourceEditor.getConsoleInfo(), parent.getFrame());
        posixGroup.initialize(observable, parent);

        
        JLabel infoLabel = new JLabel(_resource.getString("userPage","required"));
        JLabel jlGIDNumber = new JLabel( _resource.getString("Posix", "gidNumber"), SwingConstants.RIGHT);
        JLabel blankLabel = new JLabel(""); // Prevents components of this panel from centering
        componentVector.addElement(infoLabel);
        componentVector.addElement(jlGIDNumber);
       
        _cbEnable = new JCheckBox(_resource.getString("PosixGroup","enable"));
        _tfGIDNumber = new JTextField();
        jlGIDNumber.setLabelFor(_tfGIDNumber);
        componentVector.addElement(_tfGIDNumber);
        componentVector.addElement(posixGroup);
        
        _cbEnable.addActionListener(enableActionListener);
        _tfGIDNumber.addFocusListener(_focusAdaptor);
        
        JPanel p = new JPanel(new GridBagLayout());
        
        GridBagUtil.constrain(p, _cbEnable, 0, 0, GridBagConstraints.REMAINDER, 1, 0.0,
                              0.0, GridBagConstraints.NORTHWEST,
                              GridBagConstraints.HORIZONTAL,
                              SuiLookAndFeel.VERT_WINDOW_INSET,
                              SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);
        
        GridBagUtil.constrain(p, jlGIDNumber, 0, 1, 1, 1, 0.0, 0.0,
                              GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                              SuiLookAndFeel.VERT_WINDOW_INSET,
                              SuiLookAndFeel.HORIZ_WINDOW_INSET, 0, 0);
        GridBagUtil.constrain(p, _tfGIDNumber, 1, 1,
                              GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                              GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                              SuiLookAndFeel.VERT_WINDOW_INSET,
                              SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0,
                              SuiLookAndFeel.HORIZ_WINDOW_INSET);
        
        GridBagUtil.constrain(p, posixGroup, 1, 2,
                              GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                              GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                              SuiLookAndFeel.VERT_WINDOW_INSET,
                              SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE, 0,
                              SuiLookAndFeel.HORIZ_WINDOW_INSET);
        
        GridBagUtil.constrain(p, infoLabel, 1, 3,
                              GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                              GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                              SuiLookAndFeel.VERT_WINDOW_INSET,
                              SuiLookAndFeel.HORIZ_WINDOW_INSET, 0,
                              SuiLookAndFeel.HORIZ_WINDOW_INSET);
        
        GridBagUtil.constrain(p, blankLabel, 0, 4,
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
        _cbEnable.setSelected(true);
        for (int i=0; i< valueVector.size();i++){
                if (valueVector.get(i).toString().equalsIgnoreCase(_POSIXOBJECTCLASS)){
                    _cbEnable.setSelected(false);
                }
        }
        _cbEnable.doClick();
        _enableModified = false;
            
        _oldGIDNumber = observable.get(_GIDNUMBER, 0);
        _tfGIDNumber.setText(_oldGIDNumber);
    }
    
    /**
     * Implements the Observer interface. Updates the fields when notified.
     *
     * @param o    the observable object
     * @param arg  the attribute to update
     */
    public void update(Observable o, Object arg) {
        Debug.println("ResEditorPosixGroup.update: arg = " + arg);

        posixGroup.update(o,arg);
        if ((o instanceof ResourcePageObservable) == false) {
            return;
        }
        ResourcePageObservable observable = (ResourcePageObservable) o;
        if (arg instanceof String) {
            String argString = (String) arg;
            if (argString.equalsIgnoreCase(_GIDNUMBER)) {
                _tfGIDNumber.setText(observable.get(_GIDNUMBER, 0));
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
        
        Debug.println("ResEditorPosixGroup.save: observable = " + observable);
        if(_cbEnable.isSelected())
        {
            Debug.println("ResEditorPosixGroup.save: _cbEnable.isSelected");
            Vector valueVector = observable.get("objectclass");
            boolean oc_present = false;
            for (int i=0; i< valueVector.size();i++){
                if (valueVector.get(i).toString().equalsIgnoreCase(_POSIXOBJECTCLASS)){
                    oc_present = true;
                }
            }
            if (!oc_present) {
                valueVector.addElement(_POSIXOBJECTCLASS);
                observable.replace("objectclass", valueVector);
            }
            String sGIDNumber=_tfGIDNumber.getText();
            if (sGIDNumber.equals(_oldGIDNumber)==false)
            {
                observable.replace(_GIDNUMBER,sGIDNumber);
            }
            posixGroup.save(observable);
        }
        else
        {
            Debug.println("ResEditorPosixGroup.save: !_cbEnable.isSelected");
            Vector valueVector = observable.get("objectclass");
            if(valueVector.contains(_POSIXOBJECTCLASS))
                valueVector.removeElement(_POSIXOBJECTCLASS);
            observable.replace("objectclass", valueVector);
            
            observable.delete(_GIDNUMBER, "");
            observable.delete(_MEMBERUID, "");
            return true;
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
            if (_tfGIDNumber.getText().trim().length()==0) {
                SuiOptionPane.showMessageDialog(null,
                        _resource.getString("resourceEditor", "IncompleteText"),
                        _resource.getString("resourceEditor",
                        "IncompleteTitle"), SuiOptionPane.ERROR_MESSAGE);
                ModalDialogUtil.sleep();
                return false;
            }
            int testval;
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
        
        help.contextHelp("ug","ResEditorPosixGroup");
    }
}
