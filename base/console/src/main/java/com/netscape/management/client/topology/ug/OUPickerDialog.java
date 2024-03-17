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

package com.netscape.management.client.topology.ug;

import java.util.*;
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.event.*;
import com.netscape.management.client.util.*;
import com.netscape.management.client.console.ConsoleInfo;
import netscape.ldap.*;
import netscape.ldap.controls.*;
import com.netscape.management.nmclf.SuiLookAndFeel;


/**
 * Dialog which presents the organizational units available in the directory
 * server. Used to create new entries in a particular branch of the
 * directory server.
 *
 * @author  Peter Lee (phlee@netscape.com)
 */
public class OUPickerDialog extends AbstractModalDialog {

    private static ResourceSet _resource = new ResourceSet("com.netscape.management.client.topology.topology");

    private ConsoleInfo _consoleInfo;
    private JList _ouList; // Reference to JList component.
    private Help _helpSession; // For invoking help.
    private Vector _ous; // Organizational units
    private Vector _ouDNs; // Organizational unit DNs

    static private final int DISPLAY_USER_STRINGS = 0;
    static private final int DISPLAY_DNS = 1;
    private int displayMode = DISPLAY_USER_STRINGS;

    /**
     * Inner class handles mouse events.
     */
    private MouseAdapter _mouseAdaptor = new MouseAdapter() {
                public void mouseClicked(MouseEvent e) {
                    if (e.getClickCount() == 2) {
                        int index = _ouList.locationToIndex(e.getPoint());
                        if (index >= 0 && index < _ouDNs.size()) {
                            OUPickerDialog.this.setOKButtonEnabled(true);
                            OUPickerDialog.this.okInvoked();
                        }
                    }
                }
            };


    /**
     * constructor for the dialog
     *
     * @param ci  session information
     */
    public OUPickerDialog(ConsoleInfo ci) {
        // This is a modal dialog to support synchronous processing, i.e.,
        // usage involves displaying the dialog, user interacting with the
        // dialog, and the code retrieving the data from the dialog before
        // continuing.
        //super(ci.getFrame(), _resource.getString("OUPickerDialog", "Title"));
        //ci.getFrame() returns a frame but it's not the real parent.  pass null
        //and the abstract will try to figure it out.
        super(null, _resource.getString("OUPickerDialog", "Title"));

        _consoleInfo = ci;
        _ous = new Vector();
        _ouDNs = new Vector();

        _helpSession = new Help(_resource);

        JLabel prompt =
                new JLabel(_resource.getString("OUPickerDialog", "Prompt"));

        _ouList = new JList();
        prompt.setLabelFor(_ouList);
        _ouList.addListSelectionListener(
                new DialogListSelectionListener());
        _ouList.addMouseMotionListener(new DialogMouseMotionListener());
        _ouList.addMouseListener(_mouseAdaptor);
        _ouList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        JScrollPane listScroller = new JScrollPane();
        listScroller.getViewport().setView(_ouList);
        listScroller.setBorder(UIManager.getBorder("Table.scrollPaneBorder"));

        JPanel panel = new JPanel(new GridBagLayout());
        GridBagUtil.constrain(panel, prompt, 0, 0,
                              GridBagConstraints.REMAINDER, 1, 1.0, 0.0,
                              GridBagConstraints.WEST,
                              GridBagConstraints.HORIZONTAL, 
                              SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE,
                              SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE,
                              0, 0);

        GridBagUtil.constrain(panel, listScroller, 0, 1,
                              GridBagConstraints.RELATIVE,
                              GridBagConstraints.REMAINDER, 1.0, 1.0,
                              GridBagConstraints.WEST, GridBagConstraints.BOTH,
                              SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE,
                              SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE,
                              0,
                              SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE);

        String showDN = _resource.getString("OUPickerDialog", "toggle_show_dns");
        String showString = _resource.getString("OUPickerDialog", "toggle_show_strings");
        String sizingString = ((showDN != null && showDN.length() > showString.length())?showDN:showString);
        final JButton butDisplayMode = new JButton(sizingString);
        JButtonFactory.resize(butDisplayMode);
        butDisplayMode.setText(showDN);
        butDisplayMode.setToolTipText(_resource.getString("OUPickerDialog", "toggle_tt"));
        butDisplayMode.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent evt) {
                    if (displayMode == DISPLAY_DNS) {
                        displayMode = DISPLAY_USER_STRINGS;
                        butDisplayMode.setText(_resource.getString("OUPickerDialog", "toggle_show_dns"));
                    } else {
                        displayMode = DISPLAY_DNS;
                        butDisplayMode.setText(_resource.getString("OUPickerDialog", "toggle_show_strings"));
                    }
                    setOUList(displayMode);
                }
            });
        
        GridBagUtil.constrain(panel, butDisplayMode, 1, 1,
                              1,
                              GridBagConstraints.REMAINDER, 0, 0,
                              GridBagConstraints.NORTHWEST, GridBagConstraints.NONE,
                              SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE,
                              SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE,
                              SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE,
                              SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE);

        setPanel(panel);

        setMinimumSize(500, 225);
    }


    /**
      * The deprecation warning for this is wrong. This method
      * overrides Dialog.show().
      */
    public void show() {
        setOUList(this.displayMode);
        setFocusComponent(_ouList);
        setDefaultButton(OK);
        super.show();
    }


    /**
      * The deprecation warning for this is wrong. This method
      * overrides Dialog.show().
      *
      * This method takes a session info in case it has changed
      * since the last invocation. For example, the user and group
      * directory server may have been changed, and the new session
      * info object is needed to get this information.
      *
      * @param ci  session info
      */
    public void show(ConsoleInfo ci) {
        _consoleInfo = ci;
        show();
    }


    /**
      * Sets the product list.
      */
    private void setOUList(int mode) {
        Object previousSelection = _ouList.getSelectedValue();
        int previousSelectedIndex = _ouList.getSelectedIndex();
        _ouList.clearSelection();

        String filter = _resource.getString("OUPickerDialog", "SearchFilter");

        LDAPConnection ldc = _consoleInfo.getUserLDAPConnection();
        if (ldc == null) {
            Debug.println("ERROR OUPickerDialog.setOUList: no LDAP connection");
            return;
        }

        _ous.removeAllElements();
        _ouDNs.removeAllElements();

        _ouDNs.addElement(_consoleInfo.getUserBaseDN());
        if (mode == DISPLAY_USER_STRINGS) {
            _ous.addElement(_resource.getString("OUPickerDialog", "BaseDNString"));
        } else {
            _ous.addElement(_consoleInfo.getUserBaseDN());
        }

        LDAPSearchConstraints constraints = ldc.getSearchConstraints();
        if (LDAPUtil.isVersion4(ldc)) {
            LDAPSortKey key;
            String lang = Locale.getDefault().getLanguage();
            if (lang == null || lang.equals("")) {
                key = new LDAPSortKey("ou", false);
            } else {
                key = new LDAPSortKey("ou", false, lang);
            }
            constraints.setServerControls(new LDAPSortControl(key, false));
        }

        LDAPSearchResults results;
        try {
            results = ldc.search(_consoleInfo.getUserBaseDN(),
                    LDAPConnection.SCOPE_SUB, filter, null, false);

            LDAPEntry entry = null;
            while (results.hasMoreElements()) {
                entry = (LDAPEntry) results.next();
                if (mode == DISPLAY_USER_STRINGS) {
                    StringBuffer ouString = 
                        new StringBuffer(LDAPUtil.flatting( entry.getAttribute("ou",LDAPUtil.getLDAPAttributeLocale())));
                    String descValue =  LDAPUtil.flatting( entry.getAttribute("description",LDAPUtil.getLDAPAttributeLocale()));
                    if (descValue != null && !descValue.trim().equals("")) {
                        ouString.append(" (");
                        ouString.append(descValue);
                        ouString.append(")");
                    }
                    _ous.addElement(ouString.toString());
                } else {
                    _ous.addElement(entry.getDN());
                }
                _ouDNs.addElement(entry.getDN());
            }

            _ouList.setListData(_ous);
            if (previousSelection != null) {
                _ouList.setSelectedValue(previousSelection, true);
                if (_ouList.getSelectedIndex() == -1) {
                    _ouList.setSelectedIndex(previousSelectedIndex);
                }
            } else {
                _ouList.setSelectedIndex(0);
            }
            _ouList.revalidate();
            _ouList.repaint();
        } catch (LDAPException e) {
            Debug.println(
                    "ERROR OUPickerDialog.setOUList: exception during search: " + e);
            return;
        }
    }


    /**
      * Gets the index for the selected item
      *
      * @return  the index for the selected item
      */
    public int getSelectedIndex() {
        return _ouList.getSelectedIndex();
    }


    /**
      * Gets the selected object
      *
      * @return  the selected object
      */
    public Object getSelectedValue() {
        return _ouDNs.elementAt(_ouList.getSelectedIndex());
    }


    /**
      * Dismisses the dialog once the selection has been made.
      */
    public void okInvoked() {
        super.okInvoked();
    }


    /**
      * Displays help information for this dialog.
      */
    public void helpInvoked() {
        _helpSession.contextHelp("topology", "oupickerdialog");
    }


    /**
      * Inner class used to handle list mouse motion events.
      */
    class DialogMouseMotionListener implements MouseMotionListener {
        public void mouseDragged(MouseEvent e) {
            int index = _ouList.locationToIndex(e.getPoint());
            if (index >= 0 && index < _ouDNs.size()) {
                _ouList.setToolTipText((String)_ouDNs.elementAt(index));
            }
        }

        public void mouseMoved(MouseEvent e) {
            int index = _ouList.locationToIndex(e.getPoint());
            if (index >= 0 && index < _ouDNs.size()) {
                _ouList.setToolTipText((String)_ouDNs.elementAt(index));
            }
        }
    }


    /**
      * Inner class used to handle list selection events.
      */
    class DialogListSelectionListener implements ListSelectionListener {
        public void valueChanged(ListSelectionEvent e) {
            int[] selection = _ouList.getSelectedIndices();
            if (selection.length == 0) {
                OUPickerDialog.this.setOKButtonEnabled(false);
            } else {
                // Enable the action button if any item is selected.
                OUPickerDialog.this.setOKButtonEnabled(true);
            }
        }
    }
}
