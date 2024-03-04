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
package com.netscape.management.client.ace;

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import javax.swing.*;
import javax.swing.event.*;
import javax.swing.table.*;
import netscape.ldap.*;
import com.netscape.management.client.console.*;
import com.netscape.management.client.components.*;
import com.netscape.management.client.util.*;

class UGChooserDialog extends GenericDialog
{
    private static ResourceSet i18n = new ResourceSet("com.netscape.management.client.ace.ace");
    private JFrame parentFrame;
    private LDAPConnection aciLdc;
    private LDAPConnection ugLdc;
    private UGTable searchTable;
    private UGTable selectedTable;
    private JLabel searchFromLabel;
    private JButton addButton;
    private JButton removeButton;
    private JButton searchButton;
    private JButton changeButton;
    private JTextField searchField;
    private int AREA_USER = 1;
    private int AREA_GROUP = 2;
    private int AREA_ROLE = 3;    
    private int AREA_ADMIN = 4;
    private int AREA_SPECIAL = 5;
    private int selectedArea = AREA_USER;
    private String ugDN;
    
    // TODO: investigate.  used in UG Tab search pane, but appears
    // to be statically defined as "uid" in ug.ResourceEditor.
    // see topology.ug.EditUserGroupPane
    private String filterAttribute = "uid";  // used to construct search filter
    
    public UGChooserDialog(JFrame parentFrame, LDAPConnection aciLdc, LDAPConnection ugLdc, String ugDN)
    {
        super(parentFrame);
        this.parentFrame = parentFrame;
        this.aciLdc = aciLdc;
        this.ugLdc = ugLdc;
        this.ugDN = ugDN;
        setTitle(i18n("title"));
        getContentPane().add(createContentPanel());
    }
    
    private static String i18n(String id) 
    {
        return i18n.getString("ugChooser", id);
    }
    
    private JComponent createContentPanel()
    {
        JPanel p = new JPanel();
        GridBagLayout gbl = new GridBagLayout();
        p.setLayout(gbl);
        GridBagConstraints gbc = new GridBagConstraints();

        JComponent c;
        gbc.gridx = 0;       gbc.gridy = 0;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 1.0;   gbc.weighty = 0.0;
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(0, 0, 0, 0);
        c = createCriteriaPanel();
        gbl.setConstraints(c, gbc);
        p.add(c);

        gbc.gridx = 0;       gbc.gridy = 1;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 1.0;   gbc.weighty = 0.0;
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(DIFFERENT_COMPONENT_SPACE, 0, 0, 0);
        c = createSearchFromPanel();
        gbl.setConstraints(c, gbc);
        p.add(c);

        gbc.gridx = 0;       gbc.gridy = 2;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 1.0;   gbc.weighty = 1.0;
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.insets = new Insets(COMPONENT_SPACE, 0, 0, 0);
        c = createSearchPanel();
        gbl.setConstraints(c, gbc);
        p.add(c);
            
        gbc.gridx = 0;       gbc.gridy = 3;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 1.0;   gbc.weighty = 1.0;
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.insets = new Insets(COMPONENT_SPACE, 0, 0, 0);
        c = createSelectedPanel();
        gbl.setConstraints(c, gbc);
        p.add(c);
        
        ButtonFactory.resizeButtons(searchButton, changeButton);
        
        return p;
    }
    
    private JComponent createSearchFromPanel()
    {
        JPanel p = new JPanel();
        GridBagLayout gbl = new GridBagLayout();
        p.setLayout(gbl);
        GridBagConstraints gbc = new GridBagConstraints();

        gbc.gridx = 0;       gbc.gridy = 0;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 0.0;   gbc.weighty = 0.0;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.NONE;
        gbc.insets = new Insets(0, 0, 0, 0);
        JLabel textLabel = new JLabel(i18n("searchFrom"));
        gbl.setConstraints(textLabel, gbc);
        p.add(textLabel);
            
        gbc.gridx = 1;       gbc.gridy = 0;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 1.0;   gbc.weighty = 0.0;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(0, COMPONENT_SPACE, 0, 0);
        searchFromLabel = new JLabel(ugDN);
        gbl.setConstraints(searchFromLabel, gbc);
        p.add(searchFromLabel);

        gbc.gridx = 2;       gbc.gridy = 0;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 0.0;   gbc.weighty = 0.0;
        gbc.anchor = GridBagConstraints.CENTER;
        gbc.fill = GridBagConstraints.NONE;
        gbc.insets = new Insets(0, COMPONENT_SPACE, 0, 0);
        changeButton = ButtonFactory.createButton(i18n("change"), new ChangeSearchFromListener(), null);
        changeButton.setToolTipText(i18n("change_tt"));
        gbl.setConstraints(changeButton, gbc);
        p.add(changeButton);
        
        
        return p;
    }

    private JComponent createCriteriaPanel()
    {
        JPanel p = new JPanel();
        GridBagLayout gbl = new GridBagLayout();
        p.setLayout(gbl);
        GridBagConstraints gbc = new GridBagConstraints();

        gbc.gridx = 0;       gbc.gridy = 0;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 0.0;   gbc.weighty = 0.0;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.NONE;
        gbc.insets = new Insets(0, 0, 0, 0);
        JLabel textLabel = new JLabel(i18n("searchFor"));
        gbl.setConstraints(textLabel, gbc);
        p.add(textLabel);
            
        gbc.gridx = 0;       gbc.gridy = 1;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 1.0;   gbc.weighty = 0.0;
        gbc.anchor = GridBagConstraints.CENTER;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(0, 0, 0, 0);
        searchField = new JTextField();
        textLabel.setLabelFor(searchField);
        setFocusComponent(searchField);
        gbl.setConstraints(searchField, gbc);
        p.add(searchField);
            
        gbc.gridx = 1;       gbc.gridy = 0;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 0.0;   gbc.weighty = 0.0;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.NONE;
        gbc.insets = new Insets(0, COMPONENT_SPACE, 0, 0);
        textLabel = new JLabel(i18n("searchArea"));
        gbl.setConstraints(textLabel, gbc);
        p.add(textLabel);
            
        gbc.gridx = 1;       gbc.gridy = 1;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 0.0;   gbc.weighty = 0.0;
        gbc.anchor = GridBagConstraints.CENTER;
        gbc.fill = GridBagConstraints.NONE;
        gbc.insets = new Insets(0, COMPONENT_SPACE, 0, 0);
        JComboBox searchAreaCombo = new JComboBox();
        textLabel.setLabelFor(searchAreaCombo);
        searchAreaCombo.addItem(i18n("userArea"));
        searchAreaCombo.addItem(i18n("groupArea"));        
        searchAreaCombo.addItem(i18n("roleArea"));
        searchAreaCombo.addItem(i18n("adminArea"));
        searchAreaCombo.addItem(i18n("specialArea"));
        searchAreaCombo.addItemListener(new SearchAreaListener());
        gbl.setConstraints(searchAreaCombo, gbc);
        p.add(searchAreaCombo);
            
        gbc.gridx = 2;       gbc.gridy = 1;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 0.0;   gbc.weighty = 0.0;
        gbc.anchor = GridBagConstraints.CENTER;
        gbc.fill = GridBagConstraints.NONE;
        gbc.insets = new Insets(0, COMPONENT_SPACE, 0, 0);
        searchButton = ButtonFactory.createButton(i18n("search"), new SearchListener(), null);
        searchButton.setToolTipText(i18n("search_tt"));
        setDefaultButton(searchButton);
        gbl.setConstraints(searchButton, gbc);
        p.add(searchButton);
        
        return p;
    }
    
    private JComponent createSearchPanel()
    {
        JPanel p = new JPanel();
        GridBagLayout gbl = new GridBagLayout();
        p.setLayout(gbl);
        GridBagConstraints gbc = new GridBagConstraints();

        gbc.gridx = 0;       gbc.gridy = 0;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 0.0;   gbc.weighty = 0.0;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.NONE;
        gbc.insets = new Insets(0, 0, 0, 0);
        JLabel textLabel = new JLabel(i18n("searchResults"));
        gbl.setConstraints(textLabel, gbc);
        p.add(textLabel);
            
        gbc.gridx = 0;       gbc.gridy = 1;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 1.0;   gbc.weighty = 1.0;
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.insets = new Insets(0, 0, 0, 0);
        searchTable = new UGTable();
        textLabel.setLabelFor(searchTable);
        searchTable.setPreferredScrollableViewportSize(new Dimension(450, 100));
        searchTable.addFocusListener(new FocusAdapter()
            {
                public void focusGained(FocusEvent e)
                {
                    selectedTable.getSelectionModel().clearSelection();
                }
            });
        ListSelectionModel lsm = searchTable.getSelectionModel();
        lsm.addListSelectionListener(new ListSelectionListener()
            {
                public void valueChanged(ListSelectionEvent e)
                {
                    if(!e.getValueIsAdjusting())
                    {
                        addButton.setEnabled(!searchTable.getSelectionModel().isSelectionEmpty());
                    }
                }
            });
        searchTable.getModel().addTableModelListener(new TableModelListener()
            {
                public void tableChanged(TableModelEvent e)
                {
                    int count = ((TableModel)e.getSource()).getRowCount();
                    addButton.setEnabled(count > 0);
                }
            });
        
        JScrollPane sp = new JScrollPane(searchTable);
        gbl.setConstraints(sp, gbc);
        p.add(sp);
        
        return p;
    }
    
    private JComponent createSelectedPanel()
    {
        JPanel p = new JPanel();
        GridBagLayout gbl = new GridBagLayout();
        p.setLayout(gbl);
        GridBagConstraints gbc = new GridBagConstraints();

        gbc.gridx = 0;       gbc.gridy = 0;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 0.0;   gbc.weighty = 0.0;
        gbc.anchor = GridBagConstraints.SOUTHWEST;
        gbc.fill = GridBagConstraints.NONE;
        gbc.insets = new Insets(0, 0, 0, 0);
        JLabel textLabel = new JLabel(i18n("selected"));
        gbl.setConstraints(textLabel, gbc);
        p.add(textLabel);
            
        gbc.gridx = 1;       gbc.gridy = 0;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 1.0;   gbc.weighty = 0.0;
        gbc.anchor = GridBagConstraints.EAST;
        gbc.fill = GridBagConstraints.NONE;
        gbc.insets = new Insets(0, 0, COMPONENT_SPACE, 0);
        addButton = ButtonFactory.createButton(i18n("add"), new AddListener(), null);
        addButton.setToolTipText(i18n("add_tt"));
        addButton.setHorizontalTextPosition(JButton.LEFT);
        addButton.setIcon(ButtonFactory.DOWN_ICON);
        ButtonFactory.resizeButton(addButton);
        addButton.setEnabled(false);
        gbl.setConstraints(addButton, gbc);
        p.add(addButton);
            
        gbc.gridx = 2;       gbc.gridy = 0;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 0.0;   gbc.weighty = 0.0;
        gbc.anchor = GridBagConstraints.EAST;
        gbc.fill = GridBagConstraints.NONE;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE, 0);
        removeButton = ButtonFactory.createPredefinedButton(ButtonFactory.REMOVE, new RemoveListener());
        removeButton.setToolTipText(i18n("remove_tt"));
        removeButton.setIcon(ButtonFactory.UP_ICON);
        removeButton.setHorizontalTextPosition(SwingConstants.LEFT);
        removeButton.setHorizontalAlignment(SwingConstants.CENTER);
        removeButton.setMargin(new Insets(0, 15, 0, 12)); // TODO: hack - JFC does not center text+icons correctly and consistantly
        ButtonFactory.resizeButton(removeButton);
        removeButton.setEnabled(false);
        gbl.setConstraints(removeButton, gbc);
        p.add(removeButton);

        
        gbc.gridx = 0;       gbc.gridy = 1;
        gbc.gridwidth = 3;   gbc.gridheight = 1;
        gbc.weightx = 1.0;   gbc.weighty = 1.0;
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.insets = new Insets(0, 0, 0, 0);
        selectedTable = new UGTable();
        textLabel.setLabelFor(selectedTable);
        selectedTable.setPreferredScrollableViewportSize(new Dimension(450, 100));
        selectedTable.addFocusListener(new FocusAdapter()
            {
                public void focusGained(FocusEvent e)
                {
                    searchTable.getSelectionModel().clearSelection();
                }
            });
        ListSelectionModel lsm = selectedTable.getSelectionModel();
        lsm.addListSelectionListener(new ListSelectionListener()
            {
                public void valueChanged(ListSelectionEvent e)
                {
                    if(!e.getValueIsAdjusting())
                    {
                        removeButton.setEnabled(!selectedTable.getSelectionModel().isSelectionEmpty());
                    }
                }
            });
        selectedTable.getModel().addTableModelListener(new TableModelListener()
            {
                public void tableChanged(TableModelEvent e)
                {
                    int count = ((TableModel)e.getSource()).getRowCount();
                    setOKButtonEnabled(count > 0);
                    removeButton.setEnabled(count > 0);
                }
            });
        setOKButtonEnabled(false);
        JScrollPane sp = new JScrollPane(selectedTable);
        gbl.setConstraints(sp, gbc);
        p.add(sp);
        
        return p;
    }

    class ChangeSearchFromListener implements ActionListener
    {
        public void actionPerformed(ActionEvent e)
        {
            try { 
                setBusyCursor(true);

                DirBrowserDialog db = new DirBrowserDialog(parentFrame, null);            
                DirModel model = new  DirModel(aciLdc);
                model.setShowsPrivateSuffixes(false);
                model.setAllowsLeafNodes(false);
                model.setReferralsEnabled(false);
                model.initialize(null);
                db.setDirModel(model);
                db.show();
                String searchFrom = db.getSelectedDN();
                if (searchFrom == null || searchFrom.length() == 0 || db.isCancel()) {
                    return;
                }
                searchFromLabel.setText(searchFrom);
                searchFromLabel.revalidate();
                ugDN = searchFrom;
            }
            finally {
                setBusyCursor(false);
            }
        }
    }
    
    class SearchListener implements ActionListener
    {
        public void actionPerformed(ActionEvent e)
        {            
            addButton.setEnabled(false);
            searchTable.deleteAllRows();

            try {
                setBusyCursor(true);

                String query = searchField.getText(); 
                if(selectedArea == AREA_USER)
                {
                    searchTable.doSearch(ugLdc, ugDN, getUserSearchFilter(query));
                }
                else if(selectedArea == AREA_GROUP)
                {
                    searchTable.doSearch(ugLdc, ugDN, getGroupSearchFilter(query));
                }                
                else if(selectedArea == AREA_ROLE)
                {
                    searchTable.doSearch(ugLdc, ugDN, getRoleSearchFilter(query));
                }            
                else if(selectedArea == AREA_ADMIN)
                {
                    searchTable.doSearch(aciLdc, UGTab.ADMIN_BASE_DN, getUserSearchFilter(query));
                }
            }
            finally {
                setBusyCursor(false);
            }
        }
        
        String getRoleSearchFilter(String query)
        {            
            String filter = "(objectclass=ldapsubentry)(objectclass=nsRoleDefinition)";
            
            if (query == null || query.equals("") || query.equals("*")) 
            {
                filter = "(&" + filter + ")";
            } 
            else 
            {
                if (query.indexOf('*') == -1) 
                {
                    query = "*" + query + "*";
                }
                filter = "(&" + filter + "(cn=" + query + "))";
            }            
            return filter;
        }
        
        String getGroupSearchFilter(String query) {
            String filter = "(objectclass=groupofuniquenames)";

            if (query == null || query.equals("") || query.equals("*")) 
            {
                ; // use the initial filter
            } 
            else 
            {
                if (query.indexOf('*') == -1) 
                {
                    query = "*" + query + "*";
                }
                filter = "(&" + filter + "(cn=" + query + "))";
            }
            return filter;
        }
        
        String getUserSearchFilter(String query) {
            String filter = "(objectclass=person)";

            if (query == null || query.equals("") || query.equals("*")) 
            {
                ; // use the initial filter
            } 
            else 
            {
                if (query.indexOf('*') == -1) 
                {
                    query = "*" + query + "*";
                }

                if (filterAttribute.equals("cn")) 
                {
                    filter = "(&" + filter + "(cn=" + query + "))";
                }
                else 
                if (filterAttribute.equals("uid")) 
                {
                    // do not perform the substring search on UID, unless user specifically entered it.
                    String origQuery = searchField.getText();
                    filter = "(&" + filter +
                              "(|(cn=" + query + ")(" +
                               filterAttribute + "=" + origQuery + ")))";
                } 
                else 
                {
                    filter = "(&" + filter +
                              "(|(cn=" + query + ")(" +
                               filterAttribute + "=" + query + ")))";
                }
            }
            return filter;
        }
    }
    
    class AddListener implements ActionListener
    {
        public void actionPerformed(ActionEvent ev)
        {
            Vector selectedEntries = searchTable.getSelectedEntries();
            int previousRowCount = selectedTable.getRowCount();
            Enumeration e = selectedEntries.elements();
            while(e.hasMoreElements())
            {
                Object o = e.nextElement();
                if(o instanceof LDAPEntry)
                {
                    selectedTable.addRow((LDAPEntry)o);
                }
            }
            ListSelectionModel lsm = selectedTable.getSelectionModel();
            lsm.setSelectionInterval(previousRowCount, selectedTable.getRowCount()-1);
            selectedTable.grabFocus();
        }
    }
    
    class RemoveListener implements ActionListener
    {
        public void actionPerformed(ActionEvent e)
        {
            int firstSelectedRow = selectedTable.getSelectedRow() - 1;
            int index[] = selectedTable.getSelectedRows();
            if(index != null && index.length > 0)
            {
                selectedTable.deleteRows(index);
            }
            
            ListSelectionModel lsm = selectedTable.getSelectionModel();
            int rowCount = selectedTable.getRowCount();
            if(rowCount > 0)
            {
                if(firstSelectedRow < 0)
                    firstSelectedRow = 0;
                
                if(firstSelectedRow >= rowCount)
                    firstSelectedRow = rowCount;
                lsm.setSelectionInterval(firstSelectedRow, firstSelectedRow);
            }
            else
                lsm.clearSelection();
    
        }
    }
    
    class SearchAreaListener implements ItemListener
    {
        public void itemStateChanged(ItemEvent e)
        {
            if(e.getStateChange() == ItemEvent.SELECTED)
            {
                ListSelectionModel lsm = searchTable.getSelectionModel();
                lsm.clearSelection();
                Object o = e.getItem();
                if(o.equals(i18n("userArea")))
                {
                    selectedArea = AREA_USER;
                    searchTable.deleteAllRows();
                    searchTable.setUserDN(ugDN) ;
                    searchField.setBackground(UIManager.getColor("TextField.background"));
                    searchField.setEnabled(true);
                    searchButton.setEnabled(true);
                    changeButton.setEnabled(true);
                    searchFromLabel.setText(ugDN);
                    searchFromLabel.revalidate();
                }
                else
                if(o.equals(i18n("groupArea")))
                {
                    selectedArea = AREA_GROUP;
                    searchTable.deleteAllRows();
                    searchTable.setUserDN(ugDN) ;
                    searchField.setBackground(UIManager.getColor("TextField.background"));
                    searchField.setEnabled(true);
                    searchButton.setEnabled(true);
                    changeButton.setEnabled(true);
                    searchFromLabel.setText(ugDN);
                    searchFromLabel.revalidate();
                }
                else                    
                if(o.equals(i18n("roleArea")))
                {
                    selectedArea = AREA_ROLE;
                    searchTable.deleteAllRows();
                    searchTable.setUserDN(ugDN) ;
                    searchField.setBackground(UIManager.getColor("TextField.background"));
                    searchField.setEnabled(true);
                    searchButton.setEnabled(true);
                    changeButton.setEnabled(true);
                    searchFromLabel.setText(ugDN);
                    searchFromLabel.revalidate();
                }

                else
                if(o.equals(i18n("adminArea")))
                {
                    selectedArea = AREA_ADMIN;
                    searchTable.deleteAllRows();
                    searchTable.setUserDN(UGTab.ADMIN_BASE_DN) ;
                    searchField.setBackground(UIManager.getColor("TextField.background"));
                    searchField.setEnabled(true);
                    searchButton.setEnabled(true);
                    changeButton.setEnabled(false);
                    searchFromLabel.setText(UGTab.ADMIN_BASE_DN);
                    searchFromLabel.revalidate();
                }
                else // special Area
                {
                    selectedArea = AREA_SPECIAL;
                    searchField.setBackground(UIManager.getColor("control"));
                    searchField.setEnabled(false);
                    searchButton.setEnabled(false);
                    changeButton.setEnabled(false);
                    searchFromLabel.setText("");
                    searchFromLabel.revalidate();                    
                    searchTable.deleteAllRows();
                    searchTable.addRow(new LDAPEntry(UGTab.BIND_AUTHENTICATED, new LDAPAttributeSet()));
                    searchTable.addRow(new LDAPEntry(UGTab.BIND_ANYONE, new LDAPAttributeSet()));
                    searchTable.addRow(new LDAPEntry(UGTab.BIND_SELF, new LDAPAttributeSet()));
                }
            }
        }
    }
    
    /**
     * @return count of selected UG entries
     */
    public int getResultCount()
    {
        return selectedTable.getRowCount();
    }
    
    /**
     * @return specified UG entry
     */
    public LDAPEntry getResult(int index)
    {
        return selectedTable.getRow(index);
    }
    
    /**
     * Called when the Help button is pressed.
     */
    public void helpInvoked()
    {
        ConsoleHelp.showContextHelp("ace-ugchooser");
    }
}
