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
package com.netscape.management.client.acleditor;

import java.util.Enumeration;

import javax.swing.JPanel;
import javax.swing.JList;
import javax.swing.JScrollPane;
import javax.swing.DefaultListModel;

import java.util.Vector;
import java.awt.Insets;
import java.awt.GridLayout;
import java.awt.GridBagConstraints;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseListener;
import java.awt.event.MouseEvent;

import netscape.ldap.LDAPException;

import com.netscape.management.client.util.Debug;
import com.netscape.management.client.acl.LdapACL;
import com.netscape.management.client.acl.LdapACLSelector;

/**
 * The ACLSelectorWindow is called to initiate an ACL
 * Editor session and choose the aci to be edited.
 *
 * @author  <a href=mailto:dt@netscape.com>David Tompkins</a>
 * @version 0.3 5/11/98
 *
 * @see ACLEditorWindow
 * @see WindowFactory
 * @see com.netscape.management.client.acl.ACL
 * @see com.netscape.management.client.acl.Rule
 */
public class ACLSelectorWindow extends ACLEditorWindow implements LdapACLSelector,
MouseListener {
    protected JList list;
    protected DefaultListModel data;
    protected Vector aci;
    protected LdapACL acl;

    protected boolean errorOccurred = false;

    public ACLSelectorWindow(ACLEditor session) {
        super(session.getWindowFactory(), ACLSelectorName,
                session.getWindowFactory().getSessionIdentifier());

        JPanel bp = createStandardLayout();

        list = new JList(data = new DefaultListModel());
        list.addMouseListener(this);

        GridBagConstraints gbc = new GridBagConstraints();

        resetConstraints(gbc);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.ipady = PAD / 2;
        gbc.insets = new Insets(0, 0, PAD, PAD);
        bp.add(createInstruction("main2"), gbc);

        gbc.fill = GridBagConstraints.BOTH;
        gbc.weightx = gbc.weighty = 1.0;
        gbc.gridy = 1;
        gbc.gridwidth = 1;
        bp.add(new JScrollPane(list), gbc);

        JPanel p = new JPanel(new GridLayout(2, 1, PAD, PAD));
        p.add(createButton("new", new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        newACI(e);
                    }
                }
                ));
        p.add(createButton("delete", new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        deleteACI(e);
                    }
                }
                ));
        resetConstraints(gbc);
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.ipady = PAD / 2;
        gbc.insets = new Insets(0, 0, 0, 0);
        gbc.gridy = 1;
        gbc.gridx = 1;
        bp.add(p, gbc);

        setButtons();

        pack();
    }

    public synchronized void newACI(ActionEvent e) {
        // DT - clear selection, so select returns null and a new ACI is created.
        list.clearSelection();
        notifyAll();
        super.save(e);
    }

    public void deleteACI(ActionEvent e) {
        if (list.getSelectedIndex() == -1)
            return;

        String aciname = (String)(aci.elementAt(list.getSelectedIndex()));

        try {
            acl.deleteACI(aciname);
        } catch (LDAPException le) {
            showErrorDialog(LdapACL.checkLDAPError(le));
        }

        aci.removeElementAt(list.getSelectedIndex());
        data.removeElementAt(list.getSelectedIndex());
        setButtons();
    }

    public void error(LdapACL _acl, Exception e) {
        setError();
        Debug.println("ACLSelectorWindow.error: " + e.toString());
        if (e instanceof LDAPException)
            new PopupErrorDialog(this,
                    LdapACL.checkLDAPError((LDAPException) e), "errorTitle2");
        else
            new PopupErrorDialog(this, e.toString(), "errorTitle2");
    }

    public synchronized String select(LdapACL _acl, Enumeration e) {
        acl = _acl;
        aci = new Vector();

        if (e != null) {
            while (e.hasMoreElements()) {
                String aciname = (String)(e.nextElement());
                aci.addElement(aciname);
                data.addElement(LdapACL.getACLName(aciname));
            }
        }

        show();

        try {
            wait();
        } catch (InterruptedException ie) { }

        if (list.getSelectedIndex() == -1) {
            // prompt for the new aci name
            //String aciname = showInputDialog("acinameText");
            //if (aciname != null)
            //   acl.setResourceString(aciname);

            return null;
        }

        return (String)(aci.elementAt(list.getSelectedIndex()));
    }

    protected synchronized void save(ActionEvent e) {
        if (list.getSelectedIndex() == -1) {
            showErrorDialog();
            return;
        }

        notifyAll();
        super.save(e);
    }

    protected synchronized void cancel(ActionEvent e) {
        notifyAll();
        super.cancel(e);
        setError(); // Not an error, but Set Access Permissions window will open otherwise
    }

    public void setButtons() {
        getComponent("delete").setEnabled(list.getSelectedIndex() != -1);
    }

    public void mouseClicked (MouseEvent me) {
        setButtons();

        if (list.getSelectedIndex() == -1)
            return;

        if (me.getClickCount() == 2)
            save(null);
    }

    public boolean isError() {
        return errorOccurred;
    }
    public void setError() {
        errorOccurred = true;
    }

    public void mouseEntered (MouseEvent me) { }
    public void mouseExited (MouseEvent me) { }
    public void mousePressed (MouseEvent me) { }
    public void mouseReleased(MouseEvent me) { }
}
