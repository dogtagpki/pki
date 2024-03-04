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
import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;

import com.netscape.management.client.console.ConsoleInfo;


/**
 * ResEditorCertGroupMembers is a plugin for the ResourceEditor. It is used
 * when editing group membership information. This page lets administrators
 * define the group membership using certificate information.
 *
 * @see IResourceEditorPage
 * @see ResourceEditor
 * @see ResEditorGroupMembers
 */
public class ResEditorCertGroupMembers extends JPanel implements IResourceEditorPage,
Observer, ActionListener {

    PickerEditorResourceSet _resource = new PickerEditorResourceSet();
    private String ID;

    ResourceEditor _resourceEditor;
    ConsoleInfo _info;
    Vector _vList;

    // control
    JList _list;
    JButton _editButton;
    JButton _removeButton;
    JButton _addButton;

    boolean _fModified;

    Vector _vOldMembers;

    /**
    * Constructor
    *
    * @param info  session information
    */
    public ResEditorCertGroupMembers(ConsoleInfo info) {
        _info = info;
        _vList = new Vector();

        ID = _resource.getString("CertGroup", "ID");

        JLabel label = new JLabel(_resource.getString("CertGroup", "text"));

        _list = new JList(_vList);
        label.setLabelFor(_list);
        JScrollPane scrollPane = new JScrollPane(_list);
        scrollPane.setBorder(UIManager.getBorder("Table.scrollPaneBorder"));

        _addButton = new JButton(_resource.getString("groupMember", "addButton"));
        _addButton.setToolTipText(_resource.getString("CertGroup", "add_tt"));
        _addButton.addActionListener(this);
        _editButton = new JButton(_resource.getString("groupMember", "editButton"));
        _editButton.setToolTipText(_resource.getString("CertGroup", "edit_tt"));
        _editButton.addActionListener(this);
        _removeButton =
                new JButton(_resource.getString("groupMember", "removeButton"));
        _removeButton.setToolTipText(_resource.getString("CertGroup", "remove_tt"));
        _removeButton.addActionListener(this);

        JButtonFactory.resizeGroup(/*_queryButton,*/_addButton,
                _editButton, _removeButton);
        Box buttonBox = new Box(BoxLayout.X_AXIS);
        buttonBox.add(Box.createHorizontalGlue());
        //buttonBox.add(_queryButton);
        //buttonBox.add(Box.createHorizontalStrut(SuiLookAndFeel.COMPONENT_SPACE));
        buttonBox.add(_addButton);
        buttonBox.add(
                Box.createHorizontalStrut(SuiLookAndFeel.COMPONENT_SPACE));
        buttonBox.add(_editButton);
        buttonBox.add( Box.createHorizontalStrut(
                SuiLookAndFeel.SEPARATED_COMPONENT_SPACE));
        buttonBox.add(_removeButton);

        setLayout(new GridBagLayout());
        GridBagUtil.constrain(this, label, 0, 0, 1, 1, 1.0, 0.0,
                GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                SuiLookAndFeel.VERT_WINDOW_INSET,
                SuiLookAndFeel.HORIZ_WINDOW_INSET, 0,
                SuiLookAndFeel.HORIZ_WINDOW_INSET);
        GridBagUtil.constrain(this, scrollPane, 0, 1, 1, 1, 1.0, 1.0,
                GridBagConstraints.WEST, GridBagConstraints.BOTH, 0,
                SuiLookAndFeel.HORIZ_WINDOW_INSET, 0,
                SuiLookAndFeel.HORIZ_WINDOW_INSET);
        GridBagUtil.constrain(this, buttonBox, 0, 2, 1, 1, 0.0, 0.0,
                GridBagConstraints.EAST, GridBagConstraints.NONE,
                SuiLookAndFeel.SEPARATED_COMPONENT_SPACE,
                SuiLookAndFeel.COMPONENT_SPACE,
                SuiLookAndFeel.VERT_WINDOW_INSET,
                SuiLookAndFeel.HORIZ_WINDOW_INSET);
    }

    /**
     * Implements the Observer interface. Updates the fields when notified.
     *
     * @param o    the observable object
     * @param arg  the attribute to update
     */
    public void update(Observable o, Object arg) {
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
        _vOldMembers = observable.get("memberCertificateDescription");
        if (_vOldMembers != null) {
            Enumeration e = _vOldMembers.elements();
            while (e.hasMoreElements()) {
                String sString = (String) e.nextElement();
                if (sString.charAt(0) == '{') {
                    sString = sString.substring(1);
                    if (sString != "") {
                        _vList.addElement(sString);
                    }
                }
            }
            _list.setListData(_vList);
            _list.repaint();
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

        boolean fSame = true;
        if (_vList.size() == _vOldMembers.size()) {
            Enumeration eOldList = _vOldMembers.elements();
            while (eOldList.hasMoreElements()) {
                String sOldValue = (String) eOldList.nextElement();
                boolean fFound = false;
                Enumeration eNewList = _vList.elements();
                while (eNewList.hasMoreElements()) {
                    String sNewValue = (String) eNewList.nextElement();
                    if (sNewValue.equals(sOldValue)) {
                        fFound = true;
                        break;
                    }
                }
                if (!fFound) {
                    fSame = false;
                    break;
                }
            }
        } else {
            fSame = false;
        }
        if (!fSame) {
            Vector vObjectClass = observable.get("objectclass");
            if (vObjectClass.indexOf("groupOfCertificates") == -1) {
                vObjectClass.addElement("groupOfCertificates");
                observable.replace("objectclass",vObjectClass);
            }
            Enumeration e = _vList.elements();
            Vector vMembers = new Vector();
            while (e.hasMoreElements()) {
                String sString = (String) e.nextElement();
                sString = "{"+sString;
                vMembers.addElement(sString);
            }
            observable.replace("memberCertificateDescription",vMembers);
        }

        return fReturn;
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
        return _fModified;
    }

    /**
     * Implements the IResourceEditorPage interface.
      * Sets the modified flag for the page.
      *
      * @param value  true or false
     */
    public void setModified(boolean fModified) {
        _fModified = fModified;
    }

    /**
     * Implements the IResourceEditorPage interface.
      * Specifies whether the information on the page is read only.
      *
      * @return  true if some information has been modified; false otherwise
     */
    public boolean isReadOnly() {
        return false;
    }

    /**
     * Implements the IResourceEditorPage interface.
      * Sets the read only flag for the page.
      *
      * @param value  true or false
     */
    public void setReadOnly(boolean fState) {
    }

    /**
     * Implements the IResourceEditorPage interface.
      * Sets the enabled flag for the page.
      *
      * @param value  true or false
     */
    public void setEnable(boolean fEnable) {
    }

    /**
     * Implements the IResourceEditorPage interface.
      * Specifies whether all required information has been provided for
      * the page.
      *
      * @return  true if all required information has been provided; false otherwise
     */
    public boolean isComplete() {
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
     * Implements the ActionListener interface.
     *
     * @param e  the action event
     */
    public void actionPerformed(ActionEvent e) {
        if (e.getSource().equals(_addButton)) {
            // add new entry
            CertAttributeDialog d = new CertAttributeDialog(null, null);
            d.show();
            String input = d.getCertString();
            if (!input.equals("")) {
                _vList.addElement(input);
                _list.setListData(_vList);
                _list.repaint();
            }
        } else if (e.getSource().equals(_removeButton)) {
            String sSelection = (String)_list.getSelectedValue();
            if (sSelection != null) {
                _vList.removeElement(sSelection);
                _list.setListData(_vList);
                _list.repaint();
            }
        } else if (e.getSource().equals(_editButton)) {
            String sSelection = (String)_list.getSelectedValue();
            if (sSelection != null) {
                CertAttributeDialog d =
                        new CertAttributeDialog(null, sSelection);
                d.show();
                String input = d.getCertString();
                if (!input.equals("")) {
                    int index = _vList.indexOf(sSelection);
                    if (index != -1) {
                        _vList.insertElementAt(input, index);
                        _vList.removeElement(sSelection);
                        _list.setListData(_vList);
                        _list.repaint();
                    }
                }
            }
        }
    }

    /**
     * Implements the IResourceEditorPage interface.
      * Displays help information for the page
     */
    public void help() {
        Help help = new Help(_resource);

        help.contextHelp("ug","ResEditorCertGroupMembers");
    }
}


/**
  * CertAttributeDialog is used to prompt for the attributes to match
  * in the certificate.
  */
class CertAttributeDialog extends AbstractDialog {
    PickerEditorResourceSet _resource = new PickerEditorResourceSet();
    static final String sCertGroup = "CertGroup";

    boolean _fChange;
    String _sCert;

    JTextField _cn;
    JTextField _o;
    JTextField _mail;
    JTextField _c;
    JTextField _l;
    JTextField _st;
    JTextArea _ou;

    CertAttributeDialog(JFrame frame, String sCert) {
        super(frame, null, true, OK | CANCEL | HELP);
        setTitle(_resource.getString(sCertGroup, "EditDialogTitle"));
        _fChange = false;
        initializeUI();
        setCertString(sCert);
    }

    private void setCertString(String sCert) {
        if (sCert != null) {
            StringTokenizer st = new StringTokenizer(sCert, ",");
            while (st.hasMoreTokens()) {
                String s = st.nextToken();
                StringTokenizer sat = new StringTokenizer(s, "=");
                if (sat.countTokens() == 2) {
                    String sName = sat.nextToken();
                    String sValue = sat.nextToken();
                    if (sName.equalsIgnoreCase("cn")) {
                        _cn.setText(sValue);
                    } else if (sName.equalsIgnoreCase("o")) {
                        _o.setText(sValue);
                    } else if (sName.equalsIgnoreCase("l")) {
                        _l.setText(sValue);
                    } else if (sName.equalsIgnoreCase("c")) {
                        _c.setText(sValue);
                    } else if (sName.equalsIgnoreCase("st")) {
                        _st.setText(sValue);
                    } else if (sName.equalsIgnoreCase("mail")) {
                        _mail.setText(sValue);
                    } else if (sName.equalsIgnoreCase("ou")) {
                        _ou.append(sValue + "\n");
                    }
                } // if not equals to 2, skip it
            }
        }
    }

    private String appendString(String sTextField, String sString,
            String sAttribute) {
        if ((sTextField != null) && (!sTextField.equals(""))) {
            if (sString.equals("")) {
                sString = sAttribute + "="+sTextField;
            } else {
                sString += ","+sAttribute + "="+sTextField;
            }
        }
        return sString;
    }

    public String getCertString() {
        String sReturn = new String("");
        sReturn = appendString(_cn.getText(), sReturn, "cn");
        sReturn = appendString(_o.getText(), sReturn, "o");
        sReturn = appendString(_c.getText(), sReturn, "c");
        sReturn = appendString(_l.getText(), sReturn, "l");
        sReturn = appendString(_st.getText(), sReturn, "st");
        sReturn = appendString(_mail.getText(), sReturn, "mail");
        String sOU = _ou.getText();
        StringTokenizer st = new StringTokenizer(sOU);
        while (st.hasMoreTokens()) {
            sReturn = appendString(st.nextToken(), sReturn, "ou");
        }
        return sReturn;
    }

    private void initializeUI() {
        GridBagLayout layout = new GridBagLayout();

        JPanel p = new JPanel();
        p.setLayout(layout);

        GridBagUtil.constrain(p,
                new JLabel(_resource.getString(sCertGroup, "cn"),
                JLabel.RIGHT), 0, 0, 1, 1, 0.0, 0.0,
                GridBagConstraints.NORTHWEST,
                GridBagConstraints.HORIZONTAL, 0, 0, 0, 0);

        GridBagUtil.constrain(p,
                new JLabel(_resource.getString(sCertGroup, "o"),
                JLabel.RIGHT), 0, 1, 1, 1, 0.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                SuiConstants.SEPARATED_COMPONENT_SPACE, 0, 0, 0);

        GridBagUtil.constrain(p,
                new JLabel(_resource.getString(sCertGroup, "mail"),
                JLabel.RIGHT), 0, 2, 1, 1, 0.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                SuiConstants.SEPARATED_COMPONENT_SPACE, 0, 0, 0);

        GridBagUtil.constrain(p,
                new JLabel(_resource.getString(sCertGroup, "c"),
                JLabel.RIGHT), 0, 3, 1, 1, 0.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                SuiConstants.SEPARATED_COMPONENT_SPACE, 0, 0, 0);

        GridBagUtil.constrain(p,
                new JLabel(_resource.getString(sCertGroup, "l"),
                JLabel.RIGHT), 0, 4, 1, 1, 0.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                SuiConstants.SEPARATED_COMPONENT_SPACE, 0, 0, 0);

        GridBagUtil.constrain(p,
                new JLabel(_resource.getString(sCertGroup, "st"),
                JLabel.RIGHT), 0, 5, 1, 1, 0.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                SuiConstants.SEPARATED_COMPONENT_SPACE, 0, 0, 0);

        GridBagUtil.constrain(p,
                new JLabel(_resource.getString(sCertGroup, "ou"),
                JLabel.RIGHT), 0, 6, 1, 1, 0.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                SuiConstants.SEPARATED_COMPONENT_SPACE, 0, 0, 0);

        _cn = new JTextField();
        GridBagUtil.constrain(p, _cn, 1, 0,
                GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                GridBagConstraints.NORTHWEST,
                GridBagConstraints.HORIZONTAL, 0,
                SuiConstants.DIFFERENT_COMPONENT_SPACE, 0, 0);

        _o = new JTextField();
        GridBagUtil.constrain(p, _o, 1, 1,
                GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                SuiConstants.SEPARATED_COMPONENT_SPACE,
                SuiConstants.DIFFERENT_COMPONENT_SPACE, 0, 0);

        _mail = new JTextField();
        GridBagUtil.constrain(p, _mail, 1, 2,
                GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                SuiConstants.SEPARATED_COMPONENT_SPACE,
                SuiConstants.DIFFERENT_COMPONENT_SPACE, 0, 0);

        _c = new JTextField();
        GridBagUtil.constrain(p, _c, 1, 3,
                GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                SuiConstants.SEPARATED_COMPONENT_SPACE,
                SuiConstants.DIFFERENT_COMPONENT_SPACE, 0, 0);

        _l = new JTextField();
        GridBagUtil.constrain(p, _l, 1, 4,
                GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                SuiConstants.SEPARATED_COMPONENT_SPACE,
                SuiConstants.DIFFERENT_COMPONENT_SPACE, 0, 0);

        _st = new JTextField();
        GridBagUtil.constrain(p, _st, 1, 5,
                GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.HORIZONTAL,
                SuiConstants.SEPARATED_COMPONENT_SPACE,
                SuiConstants.DIFFERENT_COMPONENT_SPACE, 0, 0);

        _ou = new JTextArea();
        JScrollPane sp = new JScrollPane(_ou);
        sp.setBorder(UIManager.getBorder("Table.scrollPaneBorder"));
        GridBagUtil.constrain(p, sp, 1, 6,
                GridBagConstraints.REMAINDER, 1, 1.0, 1.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.BOTH,
                SuiConstants.SEPARATED_COMPONENT_SPACE,
                SuiConstants.DIFFERENT_COMPONENT_SPACE, 0, 0);

        setPanel(p);
        setMinimumSize(getPreferredSize());
    }

    protected void okInvoked() {
        String s = getCertString();
        super.okInvoked();
    }

    protected void helpInvoked() {
        Help help = new Help(_resource);

        help.contextHelp("ug","ResEditorCertGroupMembersEditDlg");
    }
}
