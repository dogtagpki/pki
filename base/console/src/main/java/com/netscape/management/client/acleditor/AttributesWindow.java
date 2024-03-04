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

import javax.swing.JComboBox;
import javax.swing.JTextField;
import javax.swing.JPanel;

import java.awt.event.ActionEvent;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;

import com.netscape.management.client.acl.ACL;
import com.netscape.management.client.acl.LdapACL;

/**
 * This is the dialog which let the user specifies the ACI of the attributes.
 * Through the dialog, the end user can specify all the ACI values for the given
 * attribute.
 *
 * @author  <a href=mailto:dt@netscape.com>David Tompkins</a>
 * @version 0.2 10/13/97
 */

public class AttributesWindow extends ACLEditorWindow {
    protected LdapACL acl;
    protected String equal;
    protected String notEqual;
    protected JTextField aclName;
    protected JTextField target;
    protected JComboBox targetEq;
    protected JTextField filter;
    protected JComboBox filterEq;
    protected JTextField attributes;
    protected JComboBox attributesEq;

    public AttributesWindow(String name, WindowFactory wf, ACL _acl) {
        super(wf, name, wf.getSessionIdentifier());

        acl = (LdapACL)_acl;

        equal = resources.getString(name, "equalItem");
        notEqual = resources.getString(name, "notEqualItem");

        JPanel bp = createStandardLayout();

        GridBagConstraints gbc = new GridBagConstraints();
        JPanel p = new JPanel(
                new FlowLayout(FlowLayout.RIGHT, PAD / 2, PAD / 2));
        resetConstraints(gbc);
        gbc.anchor = GridBagConstraints.EAST;
        gbc.ipady = PAD / 2;
        bp.add(p, gbc);
        p.add(createInstruction("aclName"));
        p.add(aclName = createTextField("aclName", addTextWidth, null));

        p = new JPanel(new FlowLayout(FlowLayout.RIGHT, PAD / 2, PAD / 2));
        resetConstraints(gbc);
        gbc.anchor = GridBagConstraints.EAST;
        gbc.ipady = PAD / 2;
        bp.add(p, gbc);
        p.add(createInstruction("target"));
        p.add(targetEq = createComboBox("targetEq", null));
        p.add(target = createTextField("target", addTextWidth, null));
        populateComboBoxEq(targetEq);

        p = new JPanel(new FlowLayout(FlowLayout.RIGHT, PAD / 2, PAD / 2));
        resetConstraints(gbc);
        gbc.anchor = GridBagConstraints.EAST;
        gbc.ipady = PAD / 2;
        bp.add(p, gbc);
        p.add(createInstruction("filter"));
        p.add(filterEq = createComboBox("filterEq", null));
        p.add(filter = createTextField("filter", addTextWidth, null));
        populateComboBoxEq(filterEq);

        p = new JPanel(new FlowLayout(FlowLayout.RIGHT, PAD / 2, PAD / 2));
        resetConstraints(gbc);
        gbc.anchor = GridBagConstraints.EAST;
        gbc.ipady = PAD / 2;
        bp.add(p, gbc);
        p.add(createInstruction("attributes"));
        p.add(attributesEq = createComboBox("attributesEq", null));
        p.add(attributes =
                createTextField("attributes", addTextWidth, null));
        populateComboBoxEq(attributesEq);

        setResizable(false);
        populate();

        pack();
    }

    protected void populateComboBoxEq(JComboBox box) {
        box.addItem(equal);
        box.addItem(notEqual);
    }

    protected void populate() {
        String s;

        if ((s = acl.getResourceString()) != null) {
            aclName.setText(s);
            aclName.setScrollOffset(0);
        }
        if ((s = acl.getTarget()) != null) {
            target.setText(s);
            target.setScrollOffset(0);
        }
        if ((s = acl.getTargetFilter()) != null) {
            filter.setText(s);
            filter.setScrollOffset(0);
        }
        if ((s = acl.getTargetAttributes()) != null) {
            attributes.setText(s);
            attributes.setScrollOffset(0);
        }

        targetEq.setSelectedItem(acl.getTargetEq() ? equal : notEqual);
        filterEq.setSelectedItem(acl.getTargetFilterEq() ? equal :
                notEqual);
        attributesEq.setSelectedItem(acl.getTargetAttributesEq() ?
                equal : notEqual);
    }

    protected boolean check_values() {
        if (target.getText().equals("")) {
            showErrorDialog("targetErrorText", "targetErrorTitle");
            return false;
        }

        if (attributes.getText().equals("")) {
            showErrorDialog("attributesErrorText", "attributesErrorTitle");
            return false;
        }

        return true;
    }

    protected void save(ActionEvent e) {
        if (!check_values())
            return;

        String t;

        acl.setResourceString((t = aclName.getText()).equals("") ?
                "unknown" : t);
        acl.setTarget((t = target.getText()).equals("") ? null : t);
        acl.setTargetFilter((t = filter.getText()).equals("") ? null : t);
        acl.setTargetAttributes((t = attributes.getText()).equals("") ?
                null : t);

        acl.setTargetEq(targetEq.getSelectedItem().equals(equal));
        acl.setTargetFilterEq(filterEq.getSelectedItem().equals(equal));
        acl.setTargetAttributesEq(
                attributesEq.getSelectedItem().equals(equal));

        super.save(e);
    }
}
