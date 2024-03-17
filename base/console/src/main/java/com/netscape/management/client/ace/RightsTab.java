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
import java.util.StringTokenizer;
import java.util.Vector;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumn;
import javax.swing.table.TableModel;

import com.netscape.management.client.components.ButtonFactory;
import com.netscape.management.client.components.Table;
import com.netscape.management.client.components.UIConstants;
import com.netscape.management.client.console.ConsoleHelp;
import com.netscape.management.client.util.Debug;
import com.netscape.management.client.util.ResourceSet;

import netscape.ldap.LDAPConnection;

/**
 * This tab controls which capabilities are allowed if permission is granted.
 */
class RightsTab implements IACITab, UIConstants
{
    private static ResourceSet i18n = new ResourceSet("com.netscape.management.client.ace.ace");
    private static String KEYWORD_ALLOW = "allow";
    private static String KEYWORD_DENY = "deny";
    private static String KEYWORD_ALL = "all";
    private static String KEYWORD_PROXY = "proxy";
    private static String[] RIGHTS = { "read", "compare", "search", "selfwrite", "write", "delete", "add", KEYWORD_PROXY };
    private static int TAB_POSITION = 1;
    private static String ALL_COMMAND = "ALL";
    private static String NONE_COMMAND = "NONE";
	private DefaultTableModel rightsTableModel;
    private JTable rightsTable;
    private JButton allButton;
    private JButton noneButton;
	private JPanel p = new JPanel();
	private boolean isInitialized = false;

    private static String i18n(String id)
    {
        return i18n.getString("right", id);
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
    public ACIAttribute[] aciChanged(ACIAttribute[] aciAttributes, String aciString) throws Exception
    {
        Vector usedAttributes = new Vector();
        boolean isAllow = false;
        String rightsString = null;

        for(int i = 0; i < aciAttributes.length; i++)
        {
            ACIAttribute a = aciAttributes[i];
            if(a.getName().equalsIgnoreCase(KEYWORD_ALLOW))
			{
                rightsString = a.getValue();
                isAllow = true;
                usedAttributes.addElement(a);
            }
            else
            if(a.getName().equalsIgnoreCase(KEYWORD_DENY))
			{
                rightsString = a.getValue();
                isAllow = false;
                usedAttributes.addElement(a);
            }
        }

        if(rightsString == null)
        {
            checkAll();
            return null;
        }

        Vector rightsVector = new Vector();
        rightsString = rightsString.toLowerCase();
        StringTokenizer st = new StringTokenizer(rightsString, "( ),\n");
        while(st.hasMoreTokens())
        {
            String right=st.nextToken();
            if (!isValidRightString(right))
            {
                        Debug.println("RightsTab: can not edit visually, unsupported="+right);
                        throw new Exception(i18n.getString("ed", "visualUnsupported"));
            }
            rightsVector.addElement(right);
        }

        TableModel tm = rightsTable.getModel();
        int rowCount = tm.getRowCount();
        for(int i = 0; i < rowCount; i++)
        {
            boolean state = !isAllow;
            String right = (String)tm.getValueAt(i, 1);
            if(right.equalsIgnoreCase(KEYWORD_PROXY))
            {
                if(rightsVector.contains(KEYWORD_PROXY))
                    state = isAllow;
            }
            else
            {
                if(rightsVector.contains(KEYWORD_ALL) || rightsVector.contains(right))
                    state = isAllow;
            }
            tm.setValueAt(Boolean.valueOf(state), i, 0);
        }
        return ACIAttribute.toArray(usedAttributes);
    }

    private boolean isValidRightString(String right) {
        for (int i=0; i< RIGHTS.length; i++)
        {
            if (RIGHTS[i].equalsIgnoreCase(right))
                return true;
        }
        if  (KEYWORD_ALL.equalsIgnoreCase(right))
            return true;

        return false;
    }

    /**
     * Retrieves the Component which renders the
     * content for this tab.
     *
     * @param parentFrame the Frame used by the ace dialog
     */
    public JComponent getComponent()
    {
		rightsTableModel = createTableModel();
        rightsTable = new Table(rightsTableModel, true);
        rightsTable.getAccessibleContext().setAccessibleDescription(i18n("info"));
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

        allButton = ButtonFactory.createButton(i18n("all"), buttonListener, ALL_COMMAND);
        allButton.setToolTipText(i18n("all_tt"));
        gbl.setConstraints(allButton, gbc);
        p.add(allButton);

        noneButton = ButtonFactory.createButton(i18n("none"), buttonListener, NONE_COMMAND);
        noneButton.setToolTipText(i18n("none_tt"));
        gbl.setConstraints(noneButton, gbc);
        p.add(noneButton);

        ButtonFactory.resizeButtons(allButton, noneButton);
        return p;
    }

    private DefaultTableModel createTableModel()
    {
        DefaultTableModel tm = new DefaultTableModel()
            {
                public Class getColumnClass(int c)                {                    return getValueAt(0, c).getClass();
                }

                public boolean isCellEditable(int row, int col)                {
                    return col == 0;
                }            };
        tm.addColumn(""); // column name figured out via getColumnClass()==Boolean.class
        tm.addColumn(i18n("columnName"));
        tm.addColumn(i18n("columnDesc"));
        for(int i = 0; i < RIGHTS.length; i++)
        {
            tm.addRow(new Object[] { Boolean.valueOf(false), RIGHTS[i], i18n(RIGHTS[i]) });
        }
        return tm;
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

		TableColumn col = rightsTable.getColumnModel().getColumn(0);
		col.setMinWidth(30);
		col.setMaxWidth(30);
		col.setResizable(false);
        JScrollPane sp = new JScrollPane(rightsTable);
        //sp.setPreferredSize(new Dimension(300, 200));
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
		ConsoleHelp.showContextHelp("ace-rights");
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
        String aciString = existingACI.toString();
        if(aciString.indexOf("acl") != -1)
        {
            int insertionIndex = aciString.indexOf("\";");
            if(insertionIndex != -1)
            {
                int rowCount = rightsTableModel.getRowCount();
                boolean areAllEnabled = true;
                boolean isProxyEnabled = false;
                StringBuffer newACI = new StringBuffer();
                for(int i = 0; i < rowCount; i++)
                {
                    Boolean b = (Boolean)rightsTableModel.getValueAt(i, 0);
                    String right = (String)rightsTableModel.getValueAt(i, 1);
                    if(right.equalsIgnoreCase(KEYWORD_PROXY))
                    {
                        isProxyEnabled = b.booleanValue();
                    }
                    else
                    if(b.booleanValue())
                    {
                        if(newACI.length() > 0)
                            newACI.append(",");
                        newACI.append((String)rightsTableModel.getValueAt(i, 1));
                    }
                    else
                    {
                        areAllEnabled = false;
                    }
                }

                if(areAllEnabled)
                {
                    newACI = new StringBuffer(KEYWORD_ALL);
                }

                if(isProxyEnabled)
                {
                    if(newACI.length() > 0)
                        newACI.append(",");
                    newACI.append(KEYWORD_PROXY);
                }

                if(newACI.length() > 0)
                    existingACI.insert(insertionIndex+2,  "\n" + KEYWORD_ALLOW + " (" + newACI + ")");
                else
                    existingACI.insert(insertionIndex+2,  "\n" + KEYWORD_DENY + " (" + KEYWORD_ALL + ")");

                return existingACI;
            }
        }
        System.err.println("ACI ERROR: unable to encode rights");
		return existingACI;
	}

    private void checkAll()
    {
        setAllState(true);
    }

    private void checkNone()
    {
        setAllState(false);
    }

    private void setAllState(boolean state)
    {
        int rowCount = rightsTableModel.getRowCount();
        for(int i = 0; i < rowCount; i++)
        {
            if(state == true)
            {
                String right = (String)rightsTableModel.getValueAt(i, 1);
                if(!right.equalsIgnoreCase(KEYWORD_PROXY))
                {
                    rightsTableModel.setValueAt(Boolean.valueOf(state), i, 0);
                }
            }
            else
            {
                rightsTableModel.setValueAt(Boolean.valueOf(state), i, 0);
            }
        }
        rightsTableModel.fireTableDataChanged();
    }

    class ButtonActionListener implements ActionListener
    {
        public void actionPerformed(ActionEvent e)
        {
            String actionCommand = e.getActionCommand();
            if(actionCommand.equals(ALL_COMMAND))
                checkAll();
            else
            if(actionCommand.equals(NONE_COMMAND))
                checkNone();
        }
    }

    /**
     * Returns a list of supported ACI attributes (keywords, operators, values).
     * This information is used when editing manually for the purposes of
     * syntax checking, color highlighting, and word completion.
     *
     * Alphanumeric and digit characters are treated as required literals.
     * Special characters:
     * "|"  indicates multiple choices
     */
    public ACIAttribute[] getSupportedAttributes()
    {
        StringBuffer rightsList = new StringBuffer();
        for(int i = 0; i < RIGHTS.length; i++)
        {
            rightsList.append(RIGHTS[i]);
            rightsList.append("|");
        }
        rightsList.append(KEYWORD_ALL);

        return new ACIAttribute[]
            {
                new ACIAttribute(KEYWORD_ALLOW, "", "(" + rightsList.toString() + ")"),
                new ACIAttribute(KEYWORD_ALLOW, "", "(" + KEYWORD_ALL + ")"),
                new ACIAttribute(KEYWORD_DENY, "", "(" + rightsList.toString() + ")"),
                new ACIAttribute(KEYWORD_DENY, "", "(" + KEYWORD_ALL + ")"),
            };
    }
}
