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
import javax.swing.ListSelectionModel;
import javax.swing.JCheckBox;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import java.awt.Insets;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.awt.GridBagLayout;
import java.awt.GridBagConstraints;

import com.netscape.management.client.console.ConsoleInfo;

/**
 * The ACLRuleTableWindow class implements the main ACL Editor window.
 * It is assumed that multiple editing sessions may be spawned concurrently.
 * The default implementation is designed to work with LDAP-format ACLs
 * stored in a directory server entry. The internal behaviors of the ACLRuleTableWindow
 * data tables and the internal ACL format can be customized via the
 * DataModelFactory class and the acl package. The contents of the
 * various windows can be customized via the WindowFactory class.
 *
 * @author  <a href=mailto:dt@netscape.com>David Tompkins</a>
 * @version 0.4 5/11/97
 *
 * @see DataModelFactory
 * @see WindowFactory
 * @see com.netscape.management.client.acl.ACL
 * @see com.netscape.management.client.acl.Rule
 */
public class ACLRuleTableWindow extends ACLEditorWindow implements SelectionListener {
    protected static Dimension TableSize = new Dimension(600, 200);

    protected Thread thread;
    protected ConsoleInfo info;
    protected DataModelFactory dataFactory;
    protected WindowFactory windowFactory;
    protected Table table;
    protected Table inheritedTable;
    protected JPanel inheritedPanel;

    /**
     * Creates a new ACLRuleTableWindow window.
     *
     * @param ci the ConsoleInfo object for the ACL Editor session, from
     *  which the ACL DN is pulled.
     * @param dmf a DataModelFactory to be used in place of the default
     *  DataModelFactory.
     * @param windowLabel a String to be used as the session identifier,
     *  instead of the ACL DN.
     */
    public ACLRuleTableWindow(ConsoleInfo ci, DataModelFactory dmf,
            WindowFactory wf, String windowLabel) {
        super(wf, MainWindowName, windowLabel);

        info = ci;
        dataFactory = dmf;
        windowFactory = wf;

        GridBagConstraints gbc = new GridBagConstraints();
        JPanel p;

        // Instructional text
        resetConstraints(gbc);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.ipady = 0;
        gbc.insets = new Insets(PAD, 3 * PAD / 2, PAD, 3 * PAD / 2);
        _add(createInstruction("table"), gbc);

        // Horizontal Line
        resetConstraints(gbc);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.ipady = 0;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(0, 3 * PAD / 2, 0, 3 * PAD / 2);
        _add(createHorizontalLine(), gbc);

        // Buttons and CheckBox above the Table
        resetConstraints(gbc);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.ipady = 0;
        gbc.insets = new Insets(0, PAD / 2, 0, PAD / 2);
        p = new JPanel(new FlowLayout(FlowLayout.LEFT, PAD, PAD));
        p.add(createButton("add", new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        table.addRow();
                    }
                }
                ));
        p.add(createButton("delete", new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        table.deleteRow();
                    }
                }
                ));
        p.add(createCheckBox("show", new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        showInheritedRulesSelect(e);
                    }
                }
                ));
        _add(p, gbc);

        // The Inherited Rules Table
        DataModelAdapter itdm =
                dataFactory.getInheritedTableDataModel(info);
        if (itdm != null) {
            resetConstraints(gbc);
            gbc.weightx = 1.0;
            gbc.weighty = 0.2;
            gbc.fill = GridBagConstraints.BOTH;
            gbc.ipady = 0;
            _add(inheritedPanel =
                    new JPanel(new GridLayout(1, 1, 0, 0)), gbc);
            inheritedTable = new Table(itdm);
            inheritedTable.getJTable().setRowSelectionAllowed(false);
        } else
            inheritedTable = null;

        // The Rules Table for this ACL
        DataModelAdapter dma =
                dataFactory.getTableDataModel(info, windowFactory);
        table = new Table(dma);
        table.addSelectionListener(this);
        table.setMouseOverFocusEnabled();
        resetConstraints(gbc);
        gbc.weightx = 1.0;
        gbc.weighty = 0.8;
        gbc.ipadx = 0;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.insets = new Insets(0, 3 * PAD / 2, 0, 3 * PAD / 2);
        _add(table, gbc);

        // Other Buttons below the Table
        resetConstraints(gbc);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.ipady = 0;
        gbc.insets = new Insets(0, PAD / 2, 0, PAD / 2);
        p = new JPanel(new FlowLayout(FlowLayout.LEFT, PAD, PAD));
        p.add(createButton("check", new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        checkSyntax(e);
                    }
                }
                ));
        if (((TableDataModel) dma).isTestACLAvailable())
            p.add(createButton("test", new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        testACL(e);
                    }
                }
                ));
        p.add(createButton("establish", new ActionListener() {
                    public void actionPerformed(ActionEvent e) {
                        establishAttributes(e);
                    }
                }
                ));
        _add(p, gbc);

        // Horizontal Line
        resetConstraints(gbc);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.ipady = 0;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(0, 3 * PAD / 2, 0, 3 * PAD / 2);
        _add(createHorizontalLine(), gbc);

        // Standard Window Footer
        p = createStandardFooter();
        resetConstraints(gbc);
        gbc.anchor = GridBagConstraints.EAST;
        gbc.ipady = 0;
        gbc.insets = new Insets(0, PAD / 2, 0, PAD / 2);
        _add(p, gbc);

        table.getJTable().setSelectionMode(
                ListSelectionModel.SINGLE_SELECTION);
        table.getJTable().getColumn(TableDataModel.RULE).setMaxWidth(
                RuleColumnWidth);
        table.getJTable().getColumn( TableDataModel.ALLOWDENY).setMaxWidth(
                AllowDenyColumnWidth);
        table.getJTable().setPreferredScrollableViewportSize(TableSize);

        selectionNotify(-1, -1, 0, null);

        pack();

        if (inheritedTable != null)
            setInheritedTableVisibility(false);
        else
            getComponent("show").setEnabled(false);
    }

    protected void setInheritedTableVisibility(boolean visible) {
        GridBagLayout gbl = (GridBagLayout) getContentPane().getLayout();
        GridBagConstraints gbc = gbl.getConstraints(inheritedPanel);

        if (visible) {
            inheritedPanel.add(inheritedTable);
            gbc.insets = new Insets(0, PAD, 3 * PAD / 2, PAD);
        } else {
            inheritedPanel.remove(inheritedTable);
            gbc.insets = new Insets(0, 0, 0, 0);
        }

        gbl.setConstraints(inheritedPanel, gbc);
        pack();
    }

    public void selectionNotify(int row, int col, int clickCount,
            CallbackAction cb) {
        boolean selected = !((row == -1) || (col == -1));

        getComponent("delete").setEnabled(selected);

        if (cb != null)
            cb.go(null);
    }

    protected void showInheritedRulesSelect(ActionEvent e) {
        setInheritedTableVisibility(
                ((JCheckBox) getComponent("show")).isSelected());
    }

    protected void cancel(ActionEvent e) {
        TableDataModel tdm = (TableDataModel)(table.getDataModelAdapter());
        tdm.dispose();
        super.cancel(e);
    }

    protected void save(ActionEvent e) {
        TableDataModel tdm = (TableDataModel)(table.getDataModelAdapter());

        try {
            tdm.saveData();
        } catch (Exception ex) {
            showErrorDialog(ex);
            return;
        }

        tdm.dispose();
        super.save(e);
    }

    protected void checkSyntax(ActionEvent e) {
        ((TableDataModel)(table.getDataModelAdapter())).
                showSyntaxWindow(new CallbackAction() {
                    public void callback(Object o) {
                        repaint(0);
                    }
                }
                );
    }

    protected void establishAttributes(ActionEvent e) {
        ((TableDataModel)(table.getDataModelAdapter())).
                showAttributesWindow(new CallbackAction() {
                    public void callback(Object o) {
                        repaint(0);
                    }
                }
                );
    }

    protected void testACL(ActionEvent e) {
        ((TableDataModel)(table.getDataModelAdapter())).
                showTestACLWindow(new CallbackAction() {
                    public void callback(Object o) {
                        repaint(0);
                    }
                }
                );
    }
}
