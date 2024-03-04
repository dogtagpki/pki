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

import javax.swing.JPanel;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JTextField;
import javax.swing.border.EmptyBorder;
import javax.swing.border.CompoundBorder;
import javax.swing.event.DocumentListener;
import javax.swing.event.DocumentEvent;

import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.awt.Dimension;
import java.awt.Insets;
import java.awt.GridBagLayout;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;

import java.util.Vector;
import java.util.Enumeration;

import com.netscape.management.client.ug.ResourcePickerDlg;
import com.netscape.management.client.ug.IRPCallBack;
import com.netscape.management.client.console.ConsoleInfo;
import com.netscape.management.client.util.*;

import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPAttribute;

/**
 * Base Picker window framework.
 *
 * @author  <a href=mailto:dt@netscape.com>David Tompkins</a>
 * @version 0.2 8/31/97
 */

public class PickerWindow extends ACLEditorWindow implements SelectionListener,
DocumentListener, IRPCallBack {
    protected final static int addTextWidth = 10;
    protected final static int preferredHeight = 125;

    protected static Dimension ListSize = new Dimension(600, 200);

    ConsoleInfo info;
    Table list;
    UserGroupDataModel datamodel;
    JTextField text;
    JComboBox type;
    JTextField userdnattr;
    JComboBox authmethod;
    Vector methods = new Vector();

    public PickerWindow(String name, WindowFactory wf,
            DataModelAdapter dma, ConsoleInfo ci) {
        super(wf, name, wf.getSessionIdentifier());

        info = ci;

        JPanel bp = createStandardLayout();

        GridBagConstraints gbc = new GridBagConstraints();

        // Top row
        JPanel p = new JPanel(new GridBagLayout());
        resetConstraints(gbc);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.ipady = 0;
        bp.add(p, gbc);

        JPanel p2 = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, PAD / 2));
        p2.add(type = createComboBox("selector", null));
        if (getWindowName().equals(HostsName)) {
            p2.add(text = createSingleByteTextField("addText", addTextWidth,
                    new ActionListener() {
                        public void actionPerformed(ActionEvent e) {
                            addText();
                        }
                    }
                    ));
        } else {
            p2.add(text = createTextField("addText", addTextWidth,
                    new ActionListener() {
                        public void actionPerformed(ActionEvent e) {
                            addText();
                        }
                    }
                    ));
        }
        text.getDocument().addDocumentListener(this);
        p2.add(createButton("add", new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        addText();
                    }
                }
                ));
        p2.add(createButton("remove", new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        list.deleteRow();
                    }
                }
                ));
        resetConstraints(gbc);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.ipadx = gbc.ipady = gbc.gridx = gbc.gridy = 0;
        gbc.gridwidth = 1;
        p.add(p2, gbc);

        getComponent("add").setBorder(
                new CompoundBorder(new EmptyBorder(0, PAD, 0, PAD),
                getComponent("add").getBorder()));

        p2 = new JPanel(new FlowLayout(FlowLayout.RIGHT, 0, PAD));
        // 311285: remove find button until functionality implemented
        if (!getWindowName().equals(HostsName)) {
            p2.add(createButton("find", new ActionListener() {
                        public void actionPerformed(ActionEvent e) {
                            find(e);
                        }
                    }
                    ));
        }
        resetConstraints(gbc);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.anchor = GridBagConstraints.EAST;
        gbc.ipadx = gbc.ipady = gbc.gridy = 0;
        gbc.gridx = 1;
        p.add(p2, gbc);

        // list
        resetConstraints(gbc);
        gbc.fill = GridBagConstraints.BOTH;
        gbc.weightx = gbc.weighty = 1.0;
        bp.add(list = new Table(datamodel = (UserGroupDataModel) dma), gbc);
        list.getJTable().setShowGrid(false);
        list.addSelectionListener(this);

        populateComboBox(type, datamodel);

        // Checkbox row
        p2 = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, PAD / 2));
        p2.add(createCheckBox("all", new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        toggleEquality(e);
                    }
                }
                ), gbc);
        resetConstraints(gbc);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.ipady = 0;
        gbc.ipadx = 0;
        bp.add(p2, gbc);

        // hack to include extra attributes in user/group picker
        if (getWindowName().equals(UserGroupName)) {
            // Bottom row
            p = new JPanel(new GridBagLayout());
            resetConstraints(gbc);
            gbc.fill = GridBagConstraints.HORIZONTAL;
            gbc.weightx = 1.0;
            gbc.anchor = GridBagConstraints.WEST;
            gbc.ipady = PAD / 2;
            gbc.ipadx = 0;
            gbc.insets = new Insets(PAD / 2, 0, PAD / 2, 0);
            bp.add(p, gbc);

            resetConstraints(gbc);
            gbc.anchor = GridBagConstraints.WEST;
            gbc.ipadx = gbc.ipady = gbc.gridx = gbc.gridy = 0;
            gbc.gridwidth = 1;
            gbc.insets = new Insets(0, 0, 0, PAD / 2);
            p.add(createInstruction("userdnattr"), gbc);

            resetConstraints(gbc);
            gbc.anchor = GridBagConstraints.WEST;
            gbc.fill = GridBagConstraints.HORIZONTAL;
            gbc.weightx = 1.0;
            gbc.ipadx = gbc.ipady = gbc.gridy = 0;
            gbc.gridwidth = 1;
            gbc.gridx = 1;
            p.add(userdnattr =
                    createTextField("userdnattrText", addTextWidth,
                    null), gbc);

            resetConstraints(gbc);
            gbc.anchor = GridBagConstraints.WEST;
            gbc.ipadx = gbc.ipady = gbc.gridy = 0;
            gbc.gridwidth = 1;
            gbc.gridx = 2;
            gbc.insets = new Insets(0, PAD * 2, 0, PAD / 2);
            p.add(createInstruction("authmethod"), gbc);

            resetConstraints(gbc);
            gbc.anchor = GridBagConstraints.WEST;
            gbc.fill = GridBagConstraints.HORIZONTAL;
            gbc.weightx = 1.0;
            gbc.ipadx = gbc.ipady = gbc.gridy = 0;
            gbc.gridwidth = 1;
            gbc.gridx = 3;
            p.add(authmethod = createComboBox("authmethodMenu", null), gbc);

            populateAuthMethod();
        }

        getComponent("add").setEnabled(false);
        ((JCheckBox)(getComponent("all"))).setSelected(
                !datamodel.getAttributeEquality());

        list.getJTable().setPreferredScrollableViewportSize(ListSize);

        pack();

        selectionNotify(-1, -1, 0, null);

        // hack because hosts search is unimplemented
        // 311285: remove find button until functionality implemented
        //if(getWindowName().equals(HostsName))
        //getComponent("find").setEnabled(false);

        if (getWindowName().equals(UserGroupName)) {
            userdnattr.setText(datamodel.getUserDnAttrValue());

            String am = datamodel.getAuthMethodValue();
            int index = methods.indexOf(am);

            if (index != -1) {
                authmethod.setSelectedIndex(index);
                return;
            }

            authmethod.setSelectedIndex(0); // assumed to be none
        }
    }

    protected void populateComboBox(JComboBox cb, UserGroupDataModel dm) {
        for (int i = 0 ; i < dm.getTypeCount(); i++)
            cb.addItem(resources.getString(windowName, "menuItem" + i));
    }

    protected void populateAuthMethod() {
        for (int i = 0; ;i++) {
            String item = resources.getString(windowName, "authMethod" + i);

            if (item == null)
                break;

            authmethod.addItem(item);
            methods.addElement(item);
        }

        // DT 8/18/98 Added SASL Auth Method population from the DS
        String[] sasl = datamodel.getAuthMethods();

        if (sasl == null)
            return;

        for (int i = 0 ; i < sasl.length ; i++) {
            if (sasl[i] == null)
                continue;
            authmethod.addItem(sasl[i]);
            methods.addElement(sasl[i]);
        }
    }

    public void selectionNotify(int row, int col, int clickCount,
            CallbackAction cb) {
        getComponent("remove").setEnabled((row != -1) && (col != -1));
        if (cb != null)
            cb.go(null);
    }

    protected void toggleEquality(ActionEvent e) {
        datamodel.setAttributeEquality(
                !(((JCheckBox)(getComponent("all"))).isSelected()));
    }

    protected void save(ActionEvent e) {
        if (getWindowName().equals(UserGroupName)) {
            datamodel.setUserDnAttrValue(userdnattr.getText());
            int index = authmethod.getSelectedIndex();
            if (index < 1)
                datamodel.setAuthMethodValue("");
            else
                datamodel.setAuthMethodValue(
                        (String)(methods.elementAt(index)));
        }
        datamodel.complete();
        super.save(e);
    }

    protected void find(ActionEvent e) {
        if (getWindowName().equals(HostsName)) {
            // hosts window search unimplemented
            unimplemented(e);
            return;
        }

        // user/group window search
        ResourcePickerDlg resourcePickerDlg =
                new ResourcePickerDlg(info, this, UtilConsoleGlobals.getRootFrame());
        resourcePickerDlg.setChangeDirectoryEnabled(true);
        resourcePickerDlg.show();
        resourcePickerDlg.dispose();
        //resourcePickerDlg.showModally();
        //ModalDialogUtil.dispose(resourcePickerDlg);
    }

    protected void addText() {
        String s = text.getText();

        if (s.equals(""))
            return;

        datamodel.addAttribute(s, type.getSelectedIndex());
        list.repaint(0);

        text.setText("");
    }

    public void changedUpdate(DocumentEvent e) {
        getComponent("add").setEnabled(text.getDocument().getLength() != 0);
    }
    public void insertUpdate(DocumentEvent e) {
        getComponent("add").setEnabled(text.getDocument().getLength() != 0);
    }
    public void removeUpdate(DocumentEvent e) {
        getComponent("add").setEnabled(text.getDocument().getLength() != 0);
    }

    public void getResults(Vector vResult) {
        if (vResult == null) {
            System.err.println("PickerWindow:getResults():null Vector returned from user/group picker.");
            return;
        }

        Enumeration e = vResult.elements();
        while (e.hasMoreElements()) {
            // Name is easy...
            LDAPEntry entry = ((LDAPEntry)(e.nextElement()));
            String name = entry.getDN();

            // Determining user/group type is complicated...
            boolean user = true;
            Enumeration attr = entry.getAttributeSet().getAttributes();
            while (attr.hasMoreElements()) {
                LDAPAttribute a = (LDAPAttribute)(attr.nextElement());

                if (!a.getName().equalsIgnoreCase("objectclass"))
                    continue;

                Enumeration v = a.getStringValues();
                while (v.hasMoreElements()) {
                    String val = (String)(v.nextElement());

                    if (val.equalsIgnoreCase("groupofuniquenames")) {
                        // it's a group
                        user = false;
                        break;
                    }
                }
            }

            // now add the element...
            datamodel.addAttribute(name, user ? 0 : 1);
            list.repaint(0);
        }
    }
}
