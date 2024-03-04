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

import javax.swing.JButton;
import javax.swing.JPanel;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.awt.Dimension;
import java.awt.Insets;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;

/**
 * ACI right window framework
 *
 * @author  <a href=mailto:dt@netscape.com>David Tompkins</a>
 * @version 0.2 8/31/97
 */

public class RightsWindow extends ACLEditorWindow implements SelectionListener {
    Table list;
    RightsDataModel datamodel;

    public RightsWindow(String name, WindowFactory wf,
            DataModelAdapter dma) {
        super(wf, name, wf.getSessionIdentifier());

        JPanel bp = createStandardLayout();

        GridBagConstraints gbc = new GridBagConstraints();
        resetConstraints(gbc);
        gbc.insets = new Insets(PAD, PAD / 2, 0, PAD / 2);
        bp.add(list = new Table(datamodel = (RightsDataModel) dma), gbc);
        list.setPreferredSize(new Dimension(150, 175));
        list.getJTable().setShowGrid(false);
        list.getJTable().setRowSelectionAllowed(false);
        list.addSelectionListener(this);

        resetConstraints(gbc);
        gbc.ipady = 0;
        gbc.insets = new Insets(PAD, PAD / 2, PAD / 2, PAD / 2);
        JPanel p = new JPanel(new FlowLayout(FlowLayout.CENTER, PAD, 0));
        p.add(createButton("selectAll", new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        datamodel.toggleSelectAll();
                        setSelectAllButtonLabel();
                        repaint(0);
                    }
                }
                ));
        setSelectAllButtonLabel();
        bp.add(p, gbc);

        setResizable(false);

        pack();
    }

    public void selectionNotify(int row, int col, int clickCount,
            CallbackAction cb) {
        setSelectAllButtonLabel();
    }

    protected void save(ActionEvent e) {
        String err;

        if ((err = datamodel.complete()) != null) {
            showErrorDialog("errorText"+err);
            return;
        }

        super.save(e);
    }

    protected void setSelectAllButtonLabel() {
        JButton button = (JButton) getComponent("selectAll");

        if (datamodel.getAllSelectedValue())
            button.setText(
                    resources.getString(windowName, "deselectAll" + "Button"));
        else
            button.setText(
                    resources.getString(windowName, "selectAll" + "Button"));

        button.repaint(0);
    }
}
