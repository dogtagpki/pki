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
package com.netscape.management.client.topology;

import java.awt.event.*;
import java.awt.*;
import java.util.*;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.border.*;
import netscape.ldap.*;
import com.netscape.management.client.util.*;
import com.netscape.management.client.ug.*;
import com.netscape.management.client.console.*;
import com.netscape.management.nmclf.*;

/**
 * inner class to display the user with permission
 */
class UserListRenderer extends JLabel implements ListCellRenderer {
    UserListRenderer() {
        setOpaque(true);
    }

    public Component getListCellRendererComponent(JList list,
            Object value, int index, boolean isSelected,
            boolean cellHasFocus) {
        String sTmp = value.toString();
        //setToolTipText(sTmp);
        // find the first cn=XXX,
        int iEqual = sTmp.indexOf('=');
        int iComma = sTmp.indexOf(',');
        if ((iEqual > 0) && (iComma > 0)) {
            sTmp = sTmp.substring(iEqual + 1, iComma);
        }
        setText(sTmp);
        setBackground(isSelected ?
                UIManager.getColor("List.selectionBackground") :
                UIManager.getColor("List.background"));
        setForeground(isSelected ?
                UIManager.getColor("List.selectionForeground") :
                UIManager.getColor("List.foreground"));
        return this;
    }
}

/**
  * dialog to setup user permission for the server
  */
public class PermissionDlg extends AbstractDialog implements ActionListener,
ListSelectionListener, IRPCallBack {
    JList _list;
    JScrollPane _scrollPane;
    JButton _bAddUser;
    JButton _bDeleteUser;
    JButton _bOK;
    JButton _bCancel;
    JButton _bHelp;
    String _sSIEDN;
    ConsoleInfo _info;
    Vector _vValues;
    Vector _vExtra;
    boolean _fModified;
    ResourceSet _resource = new ResourceSet("com.netscape.management.client.topology.topology");

    /**
     * constructor
     *
     * @param info global information
     * @param sSIEDN DN of the server which permission needed to be set
     */
    public PermissionDlg(ConsoleInfo info, String sSIEDN) {
        //super(info.getFrame(), true);
        //info.getFrame() does not return the correct owner of this dialog
        super(null, true);
        _info = info;
        _sSIEDN = sSIEDN;
        initialize();
        setMinimumSize(300, 400);
    }

    /**
      * Inner class used to handle window events.
      */
    class ListMouseMotionListener implements MouseMotionListener {
        public void mouseDragged(MouseEvent e) {
            int index = _list.locationToIndex(e.getPoint());
            if (index >= 0 && index < _vValues.size()) {
                _list.setToolTipText((String)_vValues.elementAt(index));
            }
        }

        public void mouseMoved(MouseEvent e) {
            int index = _list.locationToIndex(e.getPoint());
            if (index >= 0 && index < _vValues.size()) {
                _list.setToolTipText((String)_vValues.elementAt(index));
            }
        }
    }

    /**
      * create the internal controls
      */
    private JPanel createListPanel() {
        JPanel borderPanel = new JPanel();
        TitledBorder border = BorderFactory.createTitledBorder(
                _resource.getString("PermissionDlg","users"));
        border.setTitlePosition(TitledBorder.BELOW_TOP);
        borderPanel.setBorder(border);

        borderPanel.setLayout( new BorderLayout(
                SuiLookAndFeel.SEPARATED_COMPONENT_SPACE,
                SuiLookAndFeel.SEPARATED_COMPONENT_SPACE));

        _list = new JList();
        _list.getAccessibleContext().setAccessibleDescription(_resource.getString("PermissionDlg","users"));
        _list.addListSelectionListener(this);
        _list.addMouseMotionListener(new ListMouseMotionListener());
        _list.setCellRenderer(new UserListRenderer());
        _list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        _scrollPane = new JScrollPane();
        _scrollPane.getViewport().add(_list);

        borderPanel.add("Center",_scrollPane);

        JPanel controlPanel = new JPanel();
        controlPanel.setLayout(new FlowLayout(FlowLayout.RIGHT));

        _bAddUser = new JButton(_resource.getString("PermissionDlg","add"));
        _bAddUser.setToolTipText(_resource.getString("PermissionDlg","add_tt"));
        _bAddUser.addActionListener(this);
        controlPanel.add(_bAddUser);

        _bDeleteUser = new JButton(_resource.getString("PermissionDlg","delete"));
        _bDeleteUser.setToolTipText(_resource.getString("PermissionDlg","delete_tt"));
        _bDeleteUser.addActionListener(this);
        _bDeleteUser.setEnabled(false);
        controlPanel.add(_bDeleteUser);

        borderPanel.add("South",controlPanel);

        return borderPanel;
    }

    /**
      * initialize the control with the permission information
      */
    void initialize() {
        _vValues = new Vector();
        _vExtra = new Vector();

        getContentPane().setLayout(new BorderLayout());

        getContentPane().add("Center",createListPanel());

        JPanel bottomPanel = new JPanel();
        bottomPanel.setLayout(new FlowLayout(FlowLayout.RIGHT));

        _bOK = new JButton(_resource.getString("General","OK"));
        _bOK.addActionListener(this);
        bottomPanel.add(_bOK);

        _bCancel = new JButton(_resource.getString("General","Cancel"));
        _bCancel.addActionListener(this);
        bottomPanel.add(_bCancel);

        _bHelp = new JButton(_resource.getString("General","Help"));
        _bHelp.addActionListener(this);
        bottomPanel.add(_bHelp);

        getContentPane().add("South",bottomPanel);

        setTitle(_resource.getString("PermissionDlg","title"));

        // get the list of member into the list box
        try {
            LDAPConnection ldc = _info.getLDAPConnection();
            if (ldc != null) {
                LDAPEntry entry = ldc.read(_sSIEDN);
                LDAPAttribute attribute = null;
                if (entry != null) {
                    attribute = entry.getAttribute("uniquemember");
                    if (attribute != null) {
                        Enumeration eValues = attribute.getStringValues();
                        while (eValues.hasMoreElements()) {
                            Object o = eValues.nextElement();
                            String sDN = (String) o;
                            boolean fAdd = true;
                            try {
                                String attributes[] = {"objectclass"};
                                LDAPEntry entryUser =
                                        ldc.read(sDN, attributes);
                                LDAPAttributeSet attrs =
                                        entryUser.getAttributeSet();
                                Enumeration enumAttrs =
                                        attrs.getAttributes();
                                while (enumAttrs.hasMoreElements()) {
                                    LDAPAttribute anAttr = (LDAPAttribute)
                                            enumAttrs.nextElement();
                                    Enumeration enumVals =
                                            anAttr.getStringValues();
                                    while (enumVals.hasMoreElements()) {
                                        String sValue = (String)
                                                enumVals.nextElement();
                                        if (sValue.equalsIgnoreCase("netscapeserver")) {
                                            fAdd = false;
                                            _vExtra.addElement(o);
                                            break;
                                        }
                                    }
                                }
                            } catch (LDAPException e) {
                                Debug.println("PermissionDlg: Cannot load entry: "+
                                        sDN);
                            }

                            if (fAdd) {
                                _vValues.addElement(o);
                            }
                        }
                        _list.setListData(_vValues);
                        _list.repaint();
                    }
                }
            }
        } catch (LDAPException e) {
            Debug.println("Cannot read the member values for: "+_sSIEDN);
        }
        _fModified = false;
    }

    /**
      * if the user want to add a new user using the search dialog, the result will
      * return back to this functions.
      *
      * @param vResult listof resulted items' DN
      */
    public void getResults(Vector vResult) {
        Enumeration eValues = vResult.elements();
        LDAPEntry entry = null;
        Object o = null;
        while (eValues.hasMoreElements()) {
            o = eValues.nextElement();
            if ((o instanceof LDAPEntry) == false) {
                continue;
            }

            entry = (LDAPEntry) o;
            if (entry != null) {
                if (!_vValues.contains(entry.getDN())) {
                    _vValues.addElement(entry.getDN());
                    _fModified = true;
                } else {
                    SuiOptionPane.showMessageDialog(_info.getFrame(),
                            _resource.getString("error", "EntryExisted"),
                            _resource.getString("error","title"),
                            SuiOptionPane.ERROR_MESSAGE);
                    ModalDialogUtil.sleep();
                }
            }
        }
        _list.setListData(_vValues);
        _list.repaint();
    }

    /**
      * listen to the user action
      */
    public void actionPerformed(ActionEvent e) {
        if (e.getSource().equals(_bAddUser)) {
            // call Resource picker dialog and wait for call back
            setBusyCursor(true);
            ResourcePickerDlg dlg = new ResourcePickerDlg(_info, this);
            dlg.setAllowChangeDirectory(true);
            dlg.show();
            //dlg.dispose();
            setBusyCursor(false);
        } else if (e.getSource().equals(_bDeleteUser)) {
            String sSelected = (String)_list.getSelectedValue();
            _vValues.removeElement(sSelected);
            _fModified = true;
            _list.setListData(_vValues);
            _list.repaint();
        } else if (e.getSource().equals(_bOK)) {
            // save the user list to the SIE entry
            if (_fModified) {
                try {
                    LDAPConnection ldc = _info.getLDAPConnection();
                    if (ldc != null) {
                        LDAPModificationSet modifiedSet =
                                new LDAPModificationSet();
                        String sValues[] = new String[_vValues.size() +
                                _vExtra.size()];
                        Enumeration eValues = _vValues.elements();
                        Enumeration eExtra = _vExtra.elements();
                        int i = 0;
                        while (eExtra.hasMoreElements()) {
                            sValues[i] = (String) eExtra.nextElement();
                            i++;
                        }
                        while (eValues.hasMoreElements()) {
                            sValues[i] = (String) eValues.nextElement();
                            i++;
                        }
                        LDAPAttribute members =
                                new LDAPAttribute("uniqueMember",sValues);
                        modifiedSet.add(LDAPModification.REPLACE, members);
                        ldc.modify(_sSIEDN, modifiedSet);
                    }
                } catch (LDAPException eLDAPException) {
                    SuiOptionPane.showMessageDialog(_info.getFrame(),
                            _resource.getString("error",
                            "CannotChangePermission"),
                            _resource.getString("error","title"),
                            SuiOptionPane.ERROR_MESSAGE);
                    ModalDialogUtil.sleep();
                    Debug.println("cannot save the result to "+
                            _sSIEDN + " because: "+eLDAPException);
                }
            }
            setVisible(false);
        } else if (e.getSource().equals(_bCancel)) {
            setVisible(false);
        } else if (e.getSource().equals(_bHelp)) {

            Help help = new Help(_resource);
            help.contextHelp("topology","Permission");
        }
    }

    /**
      * if the list box is empty, disable the "Delete" button. So we need to listen to the listbox.
      *
      * @param event user event
      */
    public void valueChanged(ListSelectionEvent event) {
        _bDeleteUser.setEnabled(!_list.isSelectionEmpty());
    }
}
