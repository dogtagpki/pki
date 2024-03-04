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

import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Vector;

import javax.swing.BorderFactory;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.UIManager;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableModel;

import com.netscape.management.client.components.ButtonFactory;
import com.netscape.management.client.components.GenericDialog;
import com.netscape.management.client.components.Table;
import com.netscape.management.client.components.UIConstants;
import com.netscape.management.client.console.ConsoleHelp;
import com.netscape.management.client.util.RemoteImage;
import com.netscape.management.client.util.ResourceSet;

import netscape.ldap.LDAPConnection;


/**
 * This tab controls which hosts can access this object. 
 */
class HostTab implements IACITab, UIConstants
{
    private static ResourceSet i18n = new ResourceSet("com.netscape.management.client.ace.ace");
    private static RemoteImage hostIcon = new RemoteImage("com/netscape/management/client/images/host.gif");
    private static String KEYWORD_DNS = "dns";
    private static String KEYWORD_IP = "ip";
    private static String KEYWORD_OR = "or";
    private static String KEYWORD_AND = "and";
    private static int TAB_POSITION = 3;
    private JFrame parentFrame;
    private Table hostTable = null;
    private DefaultTableModel tableModel = null;
    private JButton addButton;
    private JButton removeButton;
    private JPanel p = new JPanel();
    private boolean isInitialized = false;
    private GenericDialog addHostDialog;
    private JTextField dnsField;
    private JTextField ipField;
    
    private static String i18n(String id) 
    {
        return i18n.getString("host", id);
    }
    
    /**
     * Called once to provide global information about this
     * invocation of the ACIManager.
     * 
     * @param parentFrame   a JFrame object that will be the parent for this dialog.
     * @param aciLdc        a LDAP connection to server where ACIs reside
     * @param aciDN         a DN where ACIs reside
     * @param ugLdc         a LDAP connection to server where UGs reside
     * @param ugDN          a DN where Users and Groups reside
     */
    public void initialize(JFrame parentFrame, LDAPConnection aciLdc, String aciDN, LDAPConnection ugLdc, String ugDN)
    {
        this.parentFrame = parentFrame;
    }
    
    /**
     * Notification that the ACI has changed
     * This method is called in two situations:
     * 1) during initialization, after getComponent is called.
     * 2) after a change from manual to visual mode.
     * 
     * The tab implementation should examine the changed aci and return
     * all parsed ACIAttribute objects the tab recognized and processed.
     * The return value may be null if no attributes were recognized.
     * 
     * @param aciAttributes  the aci as an array of ACIAttribute objects
     * @param rawACI         the aci string
     * @return an array of ACIAttribute objects that were recognized
     * 
     * @see ACIParser#parseACI
     * @see ACIAttribute
     */
    public ACIAttribute[] aciChanged(ACIAttribute[] aciAttributes, String aciString)
    {
        Vector usedAttributes = new Vector();
        tableModel.setNumRows(0);
        for(int i = 0; i < aciAttributes.length; i++)
        {
            ACIAttribute a = aciAttributes[i];
            if(a.getName().equalsIgnoreCase(KEYWORD_IP) || a.getName().equalsIgnoreCase(KEYWORD_DNS))
            {
                addHost(a.getValue(), a.getName().equalsIgnoreCase(KEYWORD_IP));
                usedAttributes.addElement(a);
                if(i > 0)
                {
                    ACIAttribute previousAttribute = aciAttributes[i-1];
                    String op = previousAttribute.getOperator();
                    if(op.equalsIgnoreCase(KEYWORD_OR) || op.equalsIgnoreCase(KEYWORD_AND))
                        usedAttributes.addElement(previousAttribute);
                }
            }
        }
        return ACIAttribute.toArray(usedAttributes);
    }
        
    /**
     * Retrieves the Component which renders the
     * content for this tab.
     * 
     * @param parentFrame the Frame used by the ace dialog 
     */
    public JComponent getComponent()
    {
        tableModel = createTableModel();
        hostTable = new Table(tableModel, true);
        hostTable.getAccessibleContext().setAccessibleDescription(i18n("info"));
        p.setPreferredSize(new Dimension(480, 260));
        return p;
    }
    
    /**
     * Indicates the preferred tab position in the tabbed pane.
     * Range: 0 to 10 or -1 for LAST.
     * If multiple tabs have the same preferred position,
     * the tabs are ordered by name.
     * 
     * @return the preferred tab position in the tabbed pane
     */
    public int getPreferredPosition()
    {
        return TAB_POSITION;
    }
    
    private DefaultTableModel createTableModel()
    {
        DefaultTableModel tm = new DefaultTableModel()
            {
                public Class getColumnClass(int c)                 {                    if(c == 0)
                        return JLabel.class;
                    else
                        return String.class;                }
                
                public boolean isCellEditable(int row, int col)                 {
                    return false;
                }            };
        tm.addColumn(i18n("columnName"));
        tm.addColumn(i18n("columnType"));
        return tm;
    }
    
    private JPanel createButtonPanel()
    {
        JPanel p = new JPanel();
        GridBagLayout gbl = new GridBagLayout();
        p.setLayout(gbl);
        GridBagConstraints gbc = new GridBagConstraints();

        gbc.gridx = 0;       gbc.gridy = GridBagConstraints.RELATIVE;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 1.0;   gbc.weighty = 1.0;
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.fill = GridBagConstraints.NONE;
        gbc.insets = new Insets(0, 0, COMPONENT_SPACE, 0);
        
        ActionListener buttonListener = new ButtonActionListener();
        
        addButton = ButtonFactory.createPredefinedButton(ButtonFactory.ADD, buttonListener);
        addButton.setToolTipText(i18n("add_tt"));
        gbl.setConstraints(addButton, gbc);
        p.add(addButton);
            
        removeButton = ButtonFactory.createPredefinedButton(ButtonFactory.REMOVE, buttonListener);
        removeButton.setToolTipText(i18n("remove_tt"));
        removeButton.setEnabled(false);
        gbl.setConstraints(removeButton, gbc);
        p.add(removeButton);

        ButtonFactory.resizeButtons(addButton, removeButton);
        return p;            
    }
    
    /**
     * Retrieves the title for this tab.
     * The title should be short, usually one word.
     * 
     * @return the title string for this tab.
     */
    public String getTitle()
    {
        return i18n("title");
    }

    /**
     * Notification that this tab has been selected in the UI
     */
    public void tabSelected()
    {
        if(isInitialized)
            return;
        isInitialized = true;
        
        p.setBorder(BorderFactory.createEmptyBorder(VERT_WINDOW_INSET,
                HORIZ_WINDOW_INSET, VERT_WINDOW_INSET, HORIZ_WINDOW_INSET));
        GridBagLayout gbl = new GridBagLayout();
        p.setLayout(gbl);
        GridBagConstraints gbc = new GridBagConstraints();

        gbc.gridx = 0;       gbc.gridy = 0;
        gbc.gridwidth = 2;   gbc.gridheight = 1;
        gbc.weightx = 0.0;   gbc.weighty = 0.0;
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.insets = new Insets(0, 0, 0, 0);
        JLabel infoLabel = new JLabel();
        infoLabel.setText(i18n("info"));
        gbl.setConstraints(infoLabel, gbc);
        p.add(infoLabel);
        
        gbc.gridx = 0;       gbc.gridy = 1;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 1.0;   gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.insets = new Insets(0, 0, 0, 0);
        hostTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        TableColumnModel tcm = hostTable.getColumnModel();
        tcm.getColumn(0).setWidth(150);
        hostTable.getSelectionModel().addListSelectionListener(new ListSelectionListener()
            {
                public void valueChanged(ListSelectionEvent e)
                {
                    if(!e.getValueIsAdjusting())
                    {
                        removeButton.setEnabled(!hostTable.getSelectionModel().isSelectionEmpty());
                    }
                }
            });
        hostTable.getModel().addTableModelListener(new TableModelListener()
            {
                public void tableChanged(TableModelEvent e)
                {
                    int count = ((TableModel)e.getSource()).getRowCount();
                    removeButton.setEnabled(count > 0);
                }
            });
        JScrollPane sp = new JScrollPane(hostTable);
        sp.setPreferredSize(new Dimension(300, 200));
        gbl.setConstraints(sp, gbc);
        p.add(sp);

        gbc.gridx = 1;       gbc.gridy = 1;
        gbc.weightx = 0.0;   gbc.weighty = 0.0;
        gbc.fill = GridBagConstraints.NONE;
        gbc.anchor = GridBagConstraints.NORTHEAST;
        gbc.insets = new Insets(0, SEPARATED_COMPONENT_SPACE, 0, 0);
        JPanel buttonPanel = createButtonPanel();
        gbl.setConstraints(buttonPanel, gbc);
        p.add(buttonPanel);
    }
    
    /**
     * Called when the Help button is pressed.
     */
    public void helpInvoked()
    {
        ConsoleHelp.showContextHelp("ace-hosts");
    }


    /**
     * Called when the OK button is pressed.
     */
    public void okInvoked()
    {
    }

    /**
     * Called when the cancel button is pressed.
     */
    public void cancelInvoked()
    {
    }

    /**
     * Returns a new ACI that includes attributes from this tab.
     * This tab's attributes can be appended/prepended/inserted 
     * into the existingACI.
     * 
     * This method is called when in two situations:
     * 1) when the user presses OK in the ACIEditor dialog.
     * 2) after a change from visual to manual mode.
     * 
     * @param existingACI   the existing aci
     * @return the new aci that includes this tab's attributes
     */
    public StringBuffer createACI(StringBuffer existingACI)
    {
        int rowCount = tableModel.getRowCount();
        if(rowCount == 0)
            return existingACI;
        
        StringBuffer newACI = new StringBuffer();
        newACI.append(" and \n(");
        for(int i = 0; i < rowCount; i++)
        {
            JLabel filterLabel = (JLabel)hostTable.getValueAt(i, 0);
            String filterType = (filterLabel instanceof IPFilterLabel) ? KEYWORD_IP : KEYWORD_DNS;
            newACI.append(filterType + "=" + "\"" + filterLabel.getText() + "\"");
            if(i < rowCount - 1)
                newACI.append(" or \n");
        }
        newACI.append(")");
        
        if(existingACI.toString().endsWith("\n;)"))
        {
            int len = existingACI.length() - 3;
            existingACI.insert(len, newACI);
        }
        return existingACI;
    }
    
    private void showAddHostDialog()
    {
        dnsField = new JTextField(30);
        ipField = new JTextField(30);
        addHostDialog = new GenericDialog(parentFrame, "Add Host Filter");
        
        addHostDialog.getContentPane().add(createAddContentPanel());
        addHostDialog.setFocusComponent(dnsField);
        addHostDialog.setDefaultButton(GenericDialog.OK);
        addHostDialog.setOKButtonEnabled(false);
        addHostDialog.setHelpTopic("admin", "ace-addHost");
        addHostDialog.show();
        if(!addHostDialog.isCancel())
        {
            if(ipField.isEnabled())
            {
                addHost(ipField.getText(), true);
            }
            else
            {
                addHost(dnsField.getText(), false);
            }
        }
    }
    
    private void addHost(String hostFilter, boolean isIPFilter)
    {
        if(isIPFilter)
        {
            JLabel label = new IPFilterLabel(hostFilter);
            tableModel.addRow(new Object[] { label, i18n(KEYWORD_IP) });
        }
        else
        {
            JLabel label = new DNSFilterLabel(hostFilter);
            tableModel.addRow(new Object[] { label, i18n(KEYWORD_DNS) });
        }
    }
    
    private JPanel createAddContentPanel()
    {
        JPanel p = new JPanel();
        GridBagLayout gbl = new GridBagLayout();
        p.setLayout(gbl);
        GridBagConstraints gbc = new GridBagConstraints();

        gbc.gridx = 0;       gbc.gridy = 0;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 0.0;   gbc.weighty = 0.0;
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        JRadioButton dnsRadio = new JRadioButton(i18n("dialogDNS"), true);
        JPanel dnsPanel = createRadioPanel(dnsRadio, dnsField);
        dnsField.setEnabled(true);
        dnsField.getAccessibleContext().setAccessibleDescription(i18n("dialogDNS"));
        gbl.setConstraints(dnsPanel, gbc);
        p.add(dnsPanel);
        dnsField.getDocument().addDocumentListener(new DocumentListener()
            {
                public void insertUpdate(DocumentEvent e)
                {
                    stateChanged();
                }

                public void changedUpdate(DocumentEvent e)
                {
                    stateChanged();
                }

                public void removeUpdate(DocumentEvent e)
                {
                    stateChanged();
                }

                void stateChanged()
                {
                    if(dnsField.isEnabled())
                        addHostDialog.setOKButtonEnabled(dnsField.getText().length() > 0);
                }
            });
            
        gbc.gridx = 0;       gbc.gridy = 1;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 1.0;   gbc.weighty = 1.0;
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        JRadioButton ipRadio = new JRadioButton(i18n("dialogIP"), false);
        JPanel ipPanel = createRadioPanel(ipRadio, ipField);
        ipField.setEnabled(false);
        ipField.getAccessibleContext().setAccessibleDescription(i18n("dialogIP"));
        gbl.setConstraints(ipPanel, gbc);
        p.add(ipPanel);
        ipField.getDocument().addDocumentListener(new DocumentListener()
        {
            public void insertUpdate(DocumentEvent e)
            {
                stateChanged();
            }

            public void changedUpdate(DocumentEvent e)
            {
                stateChanged();
            }

            public void removeUpdate(DocumentEvent e)
            {
                stateChanged();
            }

            void stateChanged()
            {
                if(ipField.isEnabled())
                    addHostDialog.setOKButtonEnabled(ipField.getText().length() > 0);
            }
        });

        ButtonGroup g = new ButtonGroup();
        g.add(dnsRadio);
        g.add(ipRadio);
        
        return p;            
    }
    
    /**
     * temp: create label/textfield pair with shortcut support
     */
    private JPanel createRadioPanel(JRadioButton radioButton, JComponent associatedComponent)
    {
        JPanel p = new JPanel();
        GridBagLayout gbl = new GridBagLayout();
        p.setLayout(gbl);
        GridBagConstraints gbc = new GridBagConstraints();

        gbc.gridx = 0;       gbc.gridy = 0;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 0.0;   gbc.weighty = 0.0;
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(0, 0, 0, 0);
        gbl.setConstraints(radioButton, gbc);
        radioButton.addChangeListener(new RadioChangeListener(associatedComponent));
        p.add(radioButton);
            
        gbc.gridx = 0;       gbc.gridy = 1;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 1.0;   gbc.weighty = 1.0;
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(0, 18, 0, 0); // 18 = width of radio button when using NMCLF
        gbl.setConstraints(associatedComponent, gbc);
        p.add(associatedComponent);

        return p;            
    }
    
    class RadioChangeListener implements ChangeListener
    {
        JComponent c;
    
        public RadioChangeListener(JComponent associatedComponent)
        {
             c = associatedComponent;
        }
                
                
        public void stateChanged(ChangeEvent e)
        {
            JRadioButton rb = (JRadioButton)e.getSource();
            boolean state = rb.isSelected();
            c.setEnabled(state);
            if(c instanceof JTextField)
            {
                c.setBackground(UIManager.getColor(state ? "TextField.background" : "control"));
            }
        }
    }

    private void removeHost()
    {
        int firstSelectedRow = hostTable.getSelectedRow() - 1;
        int index[] = hostTable.getSelectedRows();
        for(int i = 0; i < index.length; i++)
        {
            tableModel.removeRow(index[i]);
        }
        int rowCount = hostTable.getRowCount();
        if(rowCount > 0)
        {
            if(firstSelectedRow < 0)
                firstSelectedRow = 0;
            
            if(firstSelectedRow >= rowCount)
                firstSelectedRow = rowCount;
            ListSelectionModel lsm = hostTable.getSelectionModel();
            lsm.setSelectionInterval(firstSelectedRow, firstSelectedRow);
        }
    }
    
    
    class ButtonActionListener implements ActionListener
    {
        public void actionPerformed(ActionEvent e)
        {
            String actionCommand = e.getActionCommand();
            if(actionCommand.equals(ButtonFactory.ADD))
                showAddHostDialog();
            else
            if(actionCommand.equals(ButtonFactory.REMOVE))
                removeHost();
        }
    }
    
    class DNSFilterLabel extends JLabel
    {
        public DNSFilterLabel(String filterString)
        {
            super(filterString, hostIcon, JLabel.RIGHT);
        }
    }
    
    class IPFilterLabel extends JLabel
    {
        public IPFilterLabel(String filterString)
        {
            super(filterString, hostIcon, JLabel.RIGHT);
        }
    }
    
    /**
     * Returns a list of supported ACI attributes (keywords, operators, values).
     * This information is used when editing manually for the purposes of
     * syntax checking, color highlighting, and word completion.
     * 
     * Alphanumeric and digit characters are treated as required literals.
     * Special characters:
     * "|" used to indicate multiple choices
     */
    public ACIAttribute[] getSupportedAttributes()
    {
        return new ACIAttribute[] 
            {
                new ACIAttribute(KEYWORD_DNS, "=|!=", "\"*\""),
                new ACIAttribute(KEYWORD_IP, "=|!=", "\"*\""),
                new ACIAttribute(KEYWORD_IP, "=|!=", "\"###.###.###.###\""),
            };
    }
}
