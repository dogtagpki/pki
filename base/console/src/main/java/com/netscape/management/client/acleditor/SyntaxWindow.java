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
import javax.swing.JTextArea;
import javax.swing.JScrollPane;
import java.awt.event.ActionEvent;
import java.awt.Dimension;
import java.awt.Insets;
import java.awt.GridBagConstraints;

import com.netscape.management.client.acl.ACL;
import com.netscape.management.nmclf.SuiOptionPane;

/**
 * Syntax Editor Window
 *
 * @author  <a href=mailto:dt@netscape.com>David Tompkins</a>
 * @version 0.2 9/4/97
 */
public class SyntaxWindow extends ACLEditorWindow {
    protected int textRows = 24;
    protected int textCols = 40;

    JTextArea text;
    JScrollPane scroll;
    ACL acl;
    String oldSyntax;

    public SyntaxWindow(String name, WindowFactory wf, ACL _acl) {
        super(wf, name, wf.getSessionIdentifier());

        acl = _acl;

        JPanel bp = createStandardLayout();

        GridBagConstraints gbc = new GridBagConstraints();
        resetConstraints(gbc);
        gbc.ipady = PAD / 2;
        gbc.insets = new Insets(PAD / 2, 0, PAD / 2, 0);
        gbc.fill = GridBagConstraints.BOTH;
        gbc.weightx = gbc.weighty = 1.0;
        scroll = new JScrollPane() {
                    public Dimension getPreferredSize() {
                        return new Dimension(400, 100);
                    }
                    public float getAlignmentX() {
                        return JScrollPane.LEFT_ALIGNMENT;
                    }
                };
        bp.add(scroll, gbc);
        scroll.getViewport().add(text = createTextArea("text", null));

        text.setText(oldSyntax = acl.getSyntax());
        pack();
    }

    protected void save(ActionEvent e) {
        String newSyntax = text.getText();

        Object[] val = { resources.getString(windowName, "parseButton"),
        resources.getString(windowName, "saveAsIsButton")};
        Object[] msg = { resources.getString(windowName, "saveChoice1"),
        resources.getString(windowName, "saveChoice2"),
        resources.getString(windowName, "saveChoice3"),
        resources.getString(windowName, "saveChoice4")};

        int selection = SuiOptionPane.showOptionDialog(this, msg,
                resources.getString(windowName, "choiceTitle"),
                SuiOptionPane.DEFAULT_OPTION,
                SuiOptionPane.QUESTION_MESSAGE, null, val, val[0]);

        if (selection == 1) {
            acl.setSyntaxOverride(newSyntax);
            super.save(e);
            return;
        }

        // otherwise, parse it

        if (!(newSyntax.equals(oldSyntax)))
            ;
        acl.setSyntax(newSyntax);

        if (acl.syntaxOverrideSet()) {
            Object[] val1 = { resources.getString(windowName, "saveButton"),
            resources.getString(windowName, "cancelButton")};
            Object[] msg1 = { resources.getString(windowName, "errorText1"),
            resources.getString(windowName, "errorText2"),
            resources.getString(windowName, "errorText3")};
            selection = SuiOptionPane.showOptionDialog(this, msg1,
                    resources.getString(windowName, "errorTitle"),
                    SuiOptionPane.DEFAULT_OPTION,
                    SuiOptionPane.WARNING_MESSAGE, null, val1, val1[0]);

            if (selection == 1)
                acl.clearSyntaxOverride(); // cancel override
        }

        super.save(e);
    }
}
