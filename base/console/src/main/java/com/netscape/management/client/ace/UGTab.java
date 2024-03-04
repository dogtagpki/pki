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
import netscape.ldap.util.*;
import com.netscape.management.client.console.ConsoleHelp;
import com.netscape.management.client.components.*;
import com.netscape.management.client.util.*;

/**
 * This tab controls who can access this object.
 */
class UGTab implements IACITab, UIConstants
{
    private static ResourceSet i18n = new ResourceSet("com.netscape.management.client.ace.ace");
    private static String KEYWORD_USERDN = "userdn";
    private static String KEYWORD_GROUPDN = "groupdn";
    private static String KEYWORD_ROLEDN = "roledn";
    private static String KEYWORD_OR = "or";
    private static String KEYWORD_AND = "and";
    private static int TAB_POSITION = 0;
    public static String ADMIN_BASE_DN = "ou=Administrators, ou=TopologyManagement, o=netscapeRoot";
	public static String BIND_PREFIX = "ldap:///";
	public static String BIND_AUTHENTICATED = "all";
	public static String BIND_ANYONE = "anyone";
	public static String BIND_SELF = "self";
    private JFrame parentFrame;
	private UGTable ugTable;
    private JButton addButton;
    private JButton removeButton;
    private LDAPConnection aciLdc;
    private LDAPConnection ugLdc;
	private String ugDN; // user and group area
	private JPanel p = new JPanel();
	private boolean isInitialized = false;
    
    public static String i18n(String id) 
    {
        return i18n.getString("ug", id);
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
        this.aciLdc = aciLdc;
        this.ugLdc = ugLdc;
		this.ugDN = ugDN;
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
    public ACIAttribute[] aciChanged(ACIAttribute[] aciAttributes, String rawACI) throws Exception
    {
        Vector usedAttributes = new Vector();
        ugTable.deleteAllRows();
        
        for(int i = 0; i < aciAttributes.length; i++)
        {
            ACIAttribute a = aciAttributes[i];
            if(a.getName().equalsIgnoreCase(KEYWORD_USERDN) ||
               a.getName().equalsIgnoreCase(KEYWORD_GROUPDN) ||
               a.getName().equalsIgnoreCase(KEYWORD_ROLEDN))                
            {
                usedAttributes.addElement(a);
                if(i > 0)
                {
                    ACIAttribute previousAttribute = aciAttributes[i-1];
                    String op = previousAttribute.getOperator();
                    if(op.equalsIgnoreCase(KEYWORD_OR) || op.equalsIgnoreCase(KEYWORD_AND))
                        usedAttributes.addElement(previousAttribute);
                }
			    
                String dn = a.getValue();
                
				if(dn.startsWith(BIND_PREFIX))
				{
					dn = dn.substring(BIND_PREFIX.length());
                }
				if((dn.equalsIgnoreCase(BIND_AUTHENTICATED)) ||
				   (dn.equalsIgnoreCase(BIND_ANYONE)) ||
				   (dn.equalsIgnoreCase(BIND_SELF)))
                {
                    LDAPEntry entry = new LDAPEntry(dn, new LDAPAttributeSet());
				    ugTable.addRow(entry);
                    continue;
                }
                    
                if (!DN.isDN(dn))
                {
                    Debug.println("UGTab: can not edit visually, unsupported="+dn);
                    throw new Exception(i18n.getString("ed", "visualUnsupported"));
                }

                try
				{                    
                    Debug.println("UGTab: LDAP read: " + dn);
					LDAPEntry entry = ugLdc.read(dn);
					ugTable.addRow(entry);
				}
				catch(LDAPException ex)
				{
                    Debug.println("UGTab: Unable to read entry.\nException: " + ex);
                    
                    // Create an entry from the RDN and the ACI keyword
                    LDAPAttributeSet attrs = new LDAPAttributeSet();
                    Vector rdns = (new DN(dn)).getRDNs();
                    if (rdns.size() > 0) 
                    {
                        RDN rdn = (RDN) rdns.elementAt(0);
                        attrs.add(new LDAPAttribute(rdn.getType(), rdn.getValue()));
                    }
                    if (a.getName().equalsIgnoreCase(KEYWORD_USERDN))
                    {
                        attrs.add(new LDAPAttribute("objectclass", "person"));
                    }
                    else if (a.getName().equalsIgnoreCase(KEYWORD_GROUPDN))
                    {
                        attrs.add(new LDAPAttribute("objectclass", "groupofuniquenames"));
                    }
                    else if (a.getName().equalsIgnoreCase(KEYWORD_ROLEDN))
                    {
                        attrs.add(new LDAPAttribute("objectclass", "nsroledefinition"));
                    }                    
                    ugTable.addRow(new LDAPEntry(dn,attrs));
				}
            }
        }
        
        if(ugTable.getRowCount() == 0)
        {
            LDAPEntry entry = new LDAPEntry(BIND_ANYONE, new LDAPAttributeSet());
		    ugTable.addRow(entry);
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
	    ugTable = new UGTable();
        ugTable.getAccessibleContext().setAccessibleDescription(i18n("info"));
		ugTable.setPreferredScrollableViewportSize(new Dimension(300, 200));
        TableColumnModel tcm = ugTable.getColumnModel();
        tcm.getColumn(0).setPreferredWidth(200);
        tcm.getColumn(1).setPreferredWidth(50);
        tcm.getColumn(2).setPreferredWidth(50);
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
        enableButtons();
        
        return p;            
    }
    
    private void enableButtons()
    {
        removeButton.setEnabled(ugTable.getSelectedRowCount() > 0);
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
		
		ListSelectionModel lsm = ugTable.getSelectionModel();
		lsm.addListSelectionListener(new ListSelectionListener()
			{
				public void valueChanged(ListSelectionEvent e)
				{
					if(!e.getValueIsAdjusting())
					{
						removeButton.setEnabled(!ugTable.getSelectionModel().isSelectionEmpty());
					}
				}
			});
		ugTable.getModel().addTableModelListener(new TableModelListener()
			{
				public void tableChanged(TableModelEvent e)
				{
					int count = ((TableModel)e.getSource()).getRowCount();
					removeButton.setEnabled(count > 0);
				}
			});
        JScrollPane sp = new JScrollPane(ugTable);
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
		ConsoleHelp.showContextHelp("ace-ug");
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
        if(ugTable.getRowCount() <= 0)
            return existingACI;
        
        StringBuffer newACI = new StringBuffer();
        if(!existingACI.toString().endsWith(";\n;)"))
        {
            newACI.append("and");
        }
        newACI.append("\n(");
		int rowCount = ugTable.getRowCount();
        for(int i = 0; i < rowCount; i++)
        {
			LDAPEntry entry = ugTable.getRow(i);
            String dn = entry.getDN();

            if ((dn.equalsIgnoreCase(BIND_AUTHENTICATED)) ||
                (dn.equalsIgnoreCase(BIND_ANYONE)) ||
                (dn.equalsIgnoreCase(BIND_SELF))) // special rights
            {
                newACI.append(KEYWORD_USERDN);
            }
            else if (isOfType(entry, "person"))
            {
                newACI.append(KEYWORD_USERDN);
            }
            else if (isOfType(entry, "groupofuniquenames"))
            {
                newACI.append(KEYWORD_GROUPDN);
            }
            else if (isOfType(entry, "nsroledefinition"))
            {
                newACI.append(KEYWORD_ROLEDN);
            }            
            else
            {
                newACI.append("??????");
                Debug.println("UGTab ERROR: unexpected objectClass " +
                              entry.getAttribute("objectclass") +
                              "; Expecting objectClass person or groupofuniquenames or nsroledefinition");
            }
            newACI.append(" = " + "\"" + BIND_PREFIX + entry.getDN() + "\"");
	
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
	
    private boolean isOfType(LDAPEntry entry, String type)
    {
        LDAPAttribute objectclassAttr = entry.getAttribute("objectclass");
        if (objectclassAttr == null)
        {
            Debug.println("UGTab ERROR: no objectclass found in " + entry.getDN());
            return false;
        }
        String[] objectclass = objectclassAttr.getStringValueArray();
        for (int i=0; i < objectclass.length; i++)
        {
            if (objectclass[i].equalsIgnoreCase(type))
            {
                return true;
            }
        }
        return false;
    }

    private void addUser()
    {
        UGChooserDialog d = new UGChooserDialog(parentFrame, aciLdc, ugLdc, ugDN);
        d.show();
        if(!d.isCancel())
        {
            for(int i = 0; i < ugTable.getRowCount(); i++)
            {
                LDAPEntry entry = ugTable.getRow(i);
                if(entry.getDN().equals(BIND_ANYONE))
                    ugTable.deleteRow(i);
            }
			int previousRowCount = ugTable.getRowCount();
			int count = d.getResultCount();
			for(int i = 0; i < count; i++)
			{
				ugTable.addRow(d.getResult(i));
			}
            ListSelectionModel lsm = ugTable.getSelectionModel();
			lsm.setSelectionInterval(previousRowCount, ugTable.getRowCount()-1);
        }
    }
    
    private void removeUser()
    {
		int firstSelectedRow = ugTable.getSelectedRow() - 1;
		int index[] = ugTable.getSelectedRows();
		if(index != null && index.length > 0)
		{
			ugTable.deleteRows(index);
		}
        int rowCount = ugTable.getRowCount();
		if(rowCount > 0)
		{
			if(firstSelectedRow < 0)
			    firstSelectedRow = 0;
			
			if(firstSelectedRow >= rowCount)
			    firstSelectedRow = rowCount;
			ListSelectionModel lsm = ugTable.getSelectionModel();
			lsm.setSelectionInterval(firstSelectedRow, firstSelectedRow);
		}
    }
    
    private JPanel createAddContentPanel(JTextField newUGField)
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
        JLabel label = new JLabel("Enter LDAP URL of user or group:");
        gbl.setConstraints(label, gbc);
        p.add(label);
            
        gbc.gridx = 0;       gbc.gridy = 1;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 1.0;   gbc.weighty = 1.0;
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(0, 0, 0, 0);
        gbl.setConstraints(newUGField, gbc);
        p.add(newUGField);

        return p;            
    }
    
    void setBusyCursor( boolean busy) {
        
        JDialog dlg = (JDialog) SwingUtilities.getAncestorOfClass(JDialog.class, p);
        if (dlg != null) {
            Cursor cursor =  Cursor.getPredefinedCursor(
                              busy ? Cursor.WAIT_CURSOR : Cursor.DEFAULT_CURSOR);
            dlg.setCursor(cursor);
        }
    }
        
    class ButtonActionListener implements ActionListener
    {
        public void actionPerformed(ActionEvent e)
        {
            String actionCommand = e.getActionCommand();
            try { 
                setBusyCursor(true);
                if(actionCommand.equals(ButtonFactory.ADD)) 
                    addUser();
                else
                if(actionCommand.equals(ButtonFactory.REMOVE))
                    removeUser();
            }
            finally {
                setBusyCursor(false);
            }
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
     * "*" used to indicate zero or more characters
     * "#" used to indicate one numeric characters
     */
    public ACIAttribute[] getSupportedAttributes()
    {
        return new ACIAttribute[] 
            {
                new ACIAttribute(KEYWORD_USERDN, "=|!=", "\"" + BIND_PREFIX + "*" + "\""),
                new ACIAttribute(KEYWORD_USERDN, "=|!=", "\"" + BIND_PREFIX + BIND_AUTHENTICATED + "\""),
                new ACIAttribute(KEYWORD_USERDN, "=|!=", "\"" + BIND_PREFIX + BIND_ANYONE + "\""),
                new ACIAttribute(KEYWORD_USERDN, "=|!=", "\"" + BIND_PREFIX + BIND_SELF + "\""),
                new ACIAttribute(KEYWORD_GROUPDN, "=|!=", "\"" + BIND_PREFIX + "*" + "\""),
                new ACIAttribute(KEYWORD_ROLEDN, "=|!=", "\"" + BIND_PREFIX + "*" + "\"")
            };
    }
}
