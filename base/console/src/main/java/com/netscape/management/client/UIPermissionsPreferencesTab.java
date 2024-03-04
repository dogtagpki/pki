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
package com.netscape.management.client;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Enumeration;
import java.util.Vector;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.DefaultTableModel;

import com.netscape.management.client.ace.ACIManager;
import com.netscape.management.client.components.Table;
import com.netscape.management.client.console.Console;
import com.netscape.management.client.console.ConsoleHelp;
import com.netscape.management.client.console.ConsoleInfo;
import com.netscape.management.client.preferences.AbstractPreferencesTab;
import com.netscape.management.client.util.JButtonFactory;
import com.netscape.management.client.util.ResourceSet;

class UIPermissionsPreferencesTab extends AbstractPreferencesTab {
    private UIPermissions uip = null;
    private Vector permissionIDs = new Vector();
    private Table permissionTable = null;
    private DefaultTableModel permissionTableModel = null;
    private JButton permissionButton = null;
    private static ResourceSet resource = new ResourceSet("com.netscape.management.client.default");
    private static boolean isRestartRequired = false;
    private boolean isTabCreated = false;

    private static String i18n(String id) {
        return resource.getString("permTab", id);
    }

    public UIPermissionsPreferencesTab()
    {
        setTitle(i18n("title"));
    }

    /**
     * Called once to provide global information about
     * this session of the Preferences dialog.
     *
     * @param parentFrame   a JFrame object that will be the parent for this dialog.
     */
    public void initialize(JFrame parentFrame)
    {
        super.initialize(parentFrame);
        isTabCreated = false;
    }

    /**
     * Called when this tab is selected.
     * Sets the component first time tab is selected.
     */
    public void tabSelected()
    {
        if(!isTabCreated)
        {
            isTabCreated = true;
            setRestartRequired(isRestartRequired);
            setComponent(createTabPanel());
        }
    }

    /**
     * Called when the Help button is pressed.
     */
    public void helpInvoked()
    {
        ConsoleHelp.showContextHelp("preferences-uipermissions");
    }

    protected JPanel createTabPanel()
    {
        JPanel p = new JPanel();
        GridBagLayout gbl = new GridBagLayout();
        p.setLayout(gbl);
        GridBagConstraints gbc = new GridBagConstraints();
        permissionTableModel = new DefaultTableModel()
            {
                public boolean isCellEditable(int row, int column)
                {
                    return false;
                }
            };

        permissionTableModel.addColumn(i18n("nameColumn"));
        permissionTableModel.addColumn(i18n("descriptionColumn"));

        JFrame f = getFrame();
        if(f instanceof Framework)
        {
            uip = ((Framework)f).getUIPermissions();
            Enumeration e = uip.getPermissionIDs();
            while(e.hasMoreElements())
            {
                String id = (String)e.nextElement();
                permissionIDs.addElement(id);
                permissionTableModel.addRow(new String[] {uip.getName(id), uip.getDescription(id)});
            }
        }

        permissionTable = new Table(permissionTableModel, true);
        permissionTable.setToolTipText(i18n("table_tt"));
        permissionTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        ListSelectionModel lsm = permissionTable.getSelectionModel();
        lsm.addListSelectionListener(new ListSelectionListener()
            {
                public void valueChanged(ListSelectionEvent e) {
                    enableButtons();
                }
            });

        gbc.gridx = 0;       gbc.gridy = 0;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 1.0;   gbc.weighty = 1.0;
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.fill = GridBagConstraints.BOTH;
        JScrollPane sp = JTable.createScrollPaneForTable(permissionTable);
        gbl.setConstraints(sp, gbc);
        p.add(sp);

        permissionButton = JButtonFactory.create(i18n("accessButton"), new PermissionActionListener(), "permissions");
        permissionButton.setToolTipText(i18n("accessButton_tt"));
        gbc.gridx = 0;       gbc.gridy = 1;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 0.0;   gbc.weighty = 0.0;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, 0, 0, 0);
        gbl.setConstraints(permissionButton, gbc);
        p.add(permissionButton);
        enableButtons();

        return p;
    }

    private void enableButtons()
    {
        ListSelectionModel lsm = permissionTable.getSelectionModel();
        boolean state = false;
        if(!lsm.isSelectionEmpty())
        {
            int index = lsm.getMinSelectionIndex();
            state = uip.hasPermission((String)permissionIDs.elementAt(index));
        }
        permissionButton.setEnabled(state);
    }

    /**
     * Sets whether the changes made in this tab require
     * Console to be restarted in order to be effective.
     * This method preserves the state across multiple
     * invocations of this class.  It then calls
     * AbstractDialog.setRestartRequired.
     */
    private void requireRestart()
    {
        isRestartRequired = true;
        setRestartRequired(isRestartRequired);
    }


    class PermissionActionListener implements ActionListener
    {
        public void actionPerformed(ActionEvent e)
        {
            int rowIndex = permissionTable.getSelectedRow();
            if(rowIndex != -1)
            {
                ConsoleInfo ci = Console.getConsoleInfo();
                String id = (String)permissionIDs.elementAt(rowIndex);
                ACIManager acm = new ACIManager(UIPermissionsPreferencesTab.this.getFrame(), uip.getName(id), uip.getPermissionDN(id));
                acm.show();
                if(!acm.isCancel())
                {
                    requireRestart();
                }
            }
        }
    }
}
