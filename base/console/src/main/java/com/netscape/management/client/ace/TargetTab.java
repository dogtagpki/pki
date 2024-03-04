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

import java.awt.Container;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Enumeration;
import java.util.Vector;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.event.TableModelEvent;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumn;

import com.netscape.management.client.components.ButtonFactory;
import com.netscape.management.client.components.DirBrowserDialog;
import com.netscape.management.client.components.Table;
import com.netscape.management.client.components.UIConstants;
import com.netscape.management.client.console.ConsoleHelp;
import com.netscape.management.client.util.Debug;
import com.netscape.management.client.util.ResourceSet;

import netscape.ldap.LDAPAttributeSchema;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPSchema;

/**
 * This tab controls the target settings.
 */
class TargetTab implements IACITab, UIConstants
{
    private static ResourceSet i18n = new ResourceSet("com.netscape.management.client.ace.ace");
    public static String BIND_PREFIX = "ldap:///";
    private static String KEYWORD_TARGETENTRY = "target";
    private static String KEYWORD_TARGETFILTER = "targetfilter";
    private static String KEYWORD_TARGETATTRS = "targetattr";
    private static String KEYWORD_OR = "or";
    private static String KEYWORD_AND = "and";
    private static String THIS_COMMAND = "THIS";
    private static String ALL_COMMAND = "ALL";
    private static String NONE_COMMAND = "NONE";
    private static LDAPSchema schema = null;
    private static int TAB_POSITION = 2;
    private JFrame parentFrame;
    private JButton thisEntryButton = null;
    private JButton browseButton = null;
    private JButton constructButton = null;
    private JButton allButton = null;
    private JButton noneButton = null;
    private JTextField entryField = new JTextField();
    private JTextField filterField = new JTextField();
    private String selectedACIAttrs = null;
    private AttributeTableModel attrTableModel;
    private Table attrTable;
    private JScrollPane sp;
    private ActionListener buttonListener = new ButtonActionListener();
    private LDAPConnection aciLdc;
    private String aciDN;
    private JPanel p = new JPanel();
    private boolean isInitialized = false;
    private String targetEntryEquality = "=";
    private String targetFilterEquality = "=";
    private String targetAttrEquality = "=";

    private static String i18n(String id)
    {
        return i18n.getString("target", id);
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
        this.aciDN = aciDN;
    }

    /**
     * Retrieves the Component which renders the
     * content for this tab.
     *
     * @param parentFrame the Frame used by the ace dialog
     */
    public JComponent getComponent()
    {
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

    private JPanel createEntryPanel()
    {
        JPanel p = new JPanel();
        GridBagLayout gbl = new GridBagLayout();
        p.setLayout(gbl);
        GridBagConstraints gbc = new GridBagConstraints();

        gbc.gridx = 0;       gbc.gridy = 0;
        gbc.gridwidth = 3;   gbc.gridheight = 1;
        gbc.weightx = 0.0;   gbc.weighty = 0.0;
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(0, 0, 0, 0);
        JLabel targetLabel = new JLabel(i18n("entryLabel"));
        targetLabel.setLabelFor(entryField);
        gbl.setConstraints(targetLabel, gbc);
        p.add(targetLabel);

        gbc.gridx = 0;       gbc.gridy = 1;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 1.0;   gbc.weighty = 1.0;
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(0, 0, 0, 0);
        gbl.setConstraints(entryField, gbc);
        p.add(entryField);

        gbc.gridx = 1;       gbc.gridy = 1;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 0.0;   gbc.weighty = 0.0;
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.fill = GridBagConstraints.NONE;
        gbc.insets = new Insets(0, COMPONENT_SPACE, 0, 0);
        thisEntryButton = ButtonFactory.createButton(i18n("thisEntry"), buttonListener, THIS_COMMAND);
        thisEntryButton.setToolTipText(i18n("thisEntry_tt"));
        gbl.setConstraints(thisEntryButton, gbc);
        p.add(thisEntryButton);

        gbc.gridx = 2;       gbc.gridy = 1;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 0.0;   gbc.weighty = 0.0;
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.fill = GridBagConstraints.NONE;
        gbc.insets = new Insets(0, COMPONENT_SPACE, 0, 0);
        browseButton = ButtonFactory.createPredefinedButton(ButtonFactory.BROWSE, buttonListener);
        browseButton.setToolTipText(i18n("browse_tt"));
        gbl.setConstraints(browseButton, gbc);
        p.add(browseButton);

        return p;
    }

    private JPanel createFilterPanel()
    {
        JPanel p = new JPanel();
        GridBagLayout gbl = new GridBagLayout();
        p.setLayout(gbl);
        GridBagConstraints gbc = new GridBagConstraints();

        gbc.gridx = 0;       gbc.gridy = 0;
        gbc.gridwidth = 2;   gbc.gridheight = 1;
        gbc.weightx = 0.0;   gbc.weighty = 0.0;
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(0, 0, 0, 0);
        JLabel filterLabel = new JLabel(i18n("filterLabel"));
        filterLabel.setLabelFor(filterField);
        gbl.setConstraints(filterLabel, gbc);
        p.add(filterLabel);

        gbc.gridx = 0;       gbc.gridy = 1;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 1.0;   gbc.weighty = 1.0;
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(0, 0, 0, 0);
        gbl.setConstraints(filterField, gbc);
        p.add(filterField);

        gbc.gridx = 1;       gbc.gridy = 1;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 0.0;   gbc.weighty = 0.0;
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.fill = GridBagConstraints.NONE;
        gbc.insets = new Insets(0, COMPONENT_SPACE, 0, 0);
        constructButton = ButtonFactory.createButton(i18n("construct"));
        constructButton.setEnabled(false);
        constructButton.setVisible(false); // TODO: filter construction dialog
        gbl.setConstraints(constructButton, gbc);
        p.add(constructButton);

        return p;
    }

    private JPanel createAttributePanel()
    {
        JPanel p = new JPanel();
        GridBagLayout gbl = new GridBagLayout();
        p.setLayout(gbl);
        GridBagConstraints gbc = new GridBagConstraints();

        gbc.gridx = 0;       gbc.gridy = 0;
        gbc.gridwidth = 2;   gbc.gridheight = 1;
        gbc.weightx = 0.0;   gbc.weighty = 0.0;
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(0, 0, 0, 0);
        JLabel attrLabel = new JLabel(i18n("attrLabel"));
        gbl.setConstraints(attrLabel, gbc);
        p.add(attrLabel);

        gbc.gridx = 0;       gbc.gridy = 1;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 1.0;   gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.insets = new Insets(0, 0, 0, 0);
        attrTableModel = new AttributeTableModel();
        attrTable = new Table(attrTableModel, true);
        attrLabel.setLabelFor(attrTable);
        //attrTable.setAutoResizeMode(attrTable.AUTO_RESIZE_LAST_COLUMN);
        TableColumn col = attrTable.getColumnModel().getColumn(0);
        col.setMinWidth(30);
        col.setMaxWidth(30);
        col.setResizable(false);
        col = attrTable.getColumnModel().getColumn(1);
        col.setPreferredWidth(50);
        col.setWidth(50);

        sp = new JScrollPane(attrTable);
        sp.setPreferredSize(new Dimension(250, 150));
        gbl.setConstraints(sp, gbc);
        p.add(sp);

        gbc.gridx = 1;       gbc.gridy = 1;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 0.0;   gbc.weighty = 0.0;
        gbc.fill = GridBagConstraints.NONE;
        gbc.anchor = GridBagConstraints.NORTHEAST;
        gbc.insets = new Insets(SEPARATED_COMPONENT_SPACE, COMPONENT_SPACE, 0, 0);
        JPanel buttonPanel = createButtonPanel();
        gbl.setConstraints(buttonPanel, gbc);
        p.add(buttonPanel);

        return p;
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

        allButton = ButtonFactory.createButton(i18n("all"), buttonListener, ALL_COMMAND);
        allButton.setToolTipText(i18n("all_tt"));
        gbl.setConstraints(allButton, gbc);
        p.add(allButton);

        noneButton = ButtonFactory.createButton(i18n("none"), buttonListener, NONE_COMMAND);
        noneButton.setToolTipText(i18n("none_tt"));
        gbl.setConstraints(noneButton, gbc);
        p.add(noneButton);

        return p;
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
        entryField.setText("");
        filterField.setText("");
        for(int i = 0; i < aciAttributes.length; i++)
        {
            ACIAttribute a = aciAttributes[i];
            if(a.getName().equalsIgnoreCase(KEYWORD_TARGETENTRY))
            {
                String targetEntry = a.getValue();
                targetEntryEquality = a.getOperator();
                if(targetEntry.startsWith(BIND_PREFIX))
                {
                    targetEntry = targetEntry.substring(BIND_PREFIX.length());
                }
                entryField.setText(targetEntry);
                usedAttributes.addElement(a);
                if(i > 0)
                {
                    ACIAttribute previousAttribute = aciAttributes[i-1];
                    String op = previousAttribute.getOperator();
                    if(op.equalsIgnoreCase(KEYWORD_OR) || op.equalsIgnoreCase(KEYWORD_AND))
                        usedAttributes.addElement(previousAttribute);
                }
            }
            else
            if(a.getName().equalsIgnoreCase(KEYWORD_TARGETFILTER))
            {
                targetFilterEquality = a.getOperator();
                filterField.setText(a.getValue());
                usedAttributes.addElement(a);
                if(i > 0)
                {
                    ACIAttribute previousAttribute = aciAttributes[i-1];
                    String op = previousAttribute.getOperator();
                    if(op.equalsIgnoreCase(KEYWORD_OR) || op.equalsIgnoreCase(KEYWORD_AND))
                        usedAttributes.addElement(previousAttribute);
                }
            }
            else
            if(a.getName().equalsIgnoreCase(KEYWORD_TARGETATTRS))
            {
                targetAttrEquality = a.getOperator();
                selectedACIAttrs = " " + a.getValue() + " ";
                usedAttributes.addElement(a);
                if(i > 0)
                {
                    ACIAttribute previousAttribute = aciAttributes[i-1];
                    String op = previousAttribute.getOperator();
                    if(op.equalsIgnoreCase(KEYWORD_OR) || op.equalsIgnoreCase(KEYWORD_AND))
                    {
                        usedAttributes.addElement(previousAttribute);
                    }
                }
            }
        }
        if(selectedACIAttrs == null)
        {
            selectedACIAttrs = "*";
        }
        updateAttributeTable();
        if (attrTableModel != null && ! attrTable.isEnabled())
            this.setAttrEditingEnabled(true);
        return ACIAttribute.toArray(usedAttributes);
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

        gbc.gridx = 0;       gbc.gridy = GridBagConstraints.RELATIVE;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 0.0;   gbc.weighty = 0.0;
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(0, 0, COMPONENT_SPACE, 0);
        JPanel entryPanel = createEntryPanel();
        gbl.setConstraints(entryPanel, gbc);
        p.add(entryPanel);

        gbc.gridx = 0;       gbc.gridy = GridBagConstraints.RELATIVE;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 0.0;   gbc.weighty = 0.0;
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(0, 0, COMPONENT_SPACE, 0);
        JPanel filterPanel = createFilterPanel();
        gbl.setConstraints(filterPanel, gbc);
        p.add(filterPanel);

        gbc.gridx = 0;       gbc.gridy = GridBagConstraints.RELATIVE;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 1.0;   gbc.weighty = 1.0;
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.insets = new Insets(0, 0, 0, 0);
        JPanel attrPanel = createAttributePanel();
        gbl.setConstraints(attrPanel, gbc);
        p.add(attrPanel);

        ButtonFactory.resizeButtons(browseButton, constructButton, allButton, noneButton);

        Thread schemaThread = new SchemaThread(aciLdc);
        schemaThread.start();
    }

    /**
     * Called when the Help button is pressed.
     */
    public void helpInvoked()
    {
        ConsoleHelp.showContextHelp("ace-targets");
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
        String filterString = filterField.getText();
        if(filterString.length() > 0)
        {
            existingACI.insert(0, "(" + KEYWORD_TARGETFILTER + " " + targetFilterEquality + " " + filterString + ") \n");
        }

        String entryString = entryField.getText();
        if(entryString.length() > 0)
        {
            existingACI.insert(0, "(" + KEYWORD_TARGETENTRY + " " + targetEntryEquality + " \"" + BIND_PREFIX + entryString + "\") \n");
        }

        StringBuffer targetAttrs = new StringBuffer();
        if(attrTableModel == null || !attrTable.isEnabled())
        {
            targetAttrs.append(selectedACIAttrs.trim());
        }
        else
        {
            int rowCount = attrTableModel.getRowCount();
            int numSelected = 0;
            for(int i = 0; i < rowCount; i++)
            {
                Boolean selected = (Boolean)attrTableModel.getValueAt(i, 0);
                if(selected.booleanValue())
                {
                    if(numSelected > 0)
                        targetAttrs.append(" || ");
                    targetAttrs.append(attrTableModel.getValueAt(i, 1));
                    numSelected++;
                }
            }
            targetAttrEquality = "=";

            // syntax optimizations:
            if(numSelected == rowCount)  // all attrs selected
            {
                targetAttrs = new StringBuffer("*");
            }
            else
            if(numSelected > rowCount / 2)  // more efficient to do inequality
            {
                targetAttrs = new StringBuffer();
                numSelected = 0;
                for(int i = 0; i < rowCount; i++)
                {
                    Boolean selected = (Boolean)attrTableModel.getValueAt(i, 0);
                    if(!selected.booleanValue())
                    {
                        if(numSelected > 0)
                            targetAttrs.append(" || ");
                        targetAttrs.append(attrTableModel.getValueAt(i, 1));
                        numSelected++;
                    }
                }
                targetAttrEquality = "!=";
            }
        }
        existingACI.insert(0, "(" + KEYWORD_TARGETATTRS + " " + targetAttrEquality + " \"" + targetAttrs + "\") \n");

        return existingACI;
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
            if(actionCommand.equals(ButtonFactory.BROWSE))
            {
                try {
                    setBusyCursor(true);
                    DirBrowserDialog db = new DirBrowserDialog(parentFrame, aciLdc, aciDN);
                    db.show();
                    entryField.setText(db.getSelectedDN());
                }
                finally {
                    setBusyCursor(false);
                }
            }
            else
            if(actionCommand.equals(THIS_COMMAND))
            {
                entryField.setText(aciDN);
            }
            else
            if(actionCommand.equals(ALL_COMMAND))
                checkAll();
            else
            if(actionCommand.equals(NONE_COMMAND))
                checkNone();
        }
    }

    class AttributeTableModel extends DefaultTableModel
    {
        public AttributeTableModel()
        {
            addColumn(""); // column name figured out via getColumnClass()==Boolean.class
            addColumn(i18n("columnName"));
            addColumn(i18n("columnDesc"));
        }

        public Class getColumnClass(int c)        {
            if(c == 0)
                return Boolean.class;
            else
                return String.class;        }

        public boolean isCellEditable(int row, int col)        {
            return col == 0;
        }
        /**
         *  Adds a row to the end of the model.  The new row will contain
         *  <code>null</code> values unless <code>rowData</code> is specified.
         *  Notification of the row being added will be generated.
         *
         * @param   rowData          optional data of the row being added
         */
        public void addRow(Vector rowData)
        {
            if (rowData == null)
            {
                rowData = new Vector(getColumnCount());
            }
            else
            {
                rowData.setSize(getColumnCount());
            }
            dataVector.addElement(rowData);
        }

    }

    // Replace all '||' with a space and enclose the whole string in spaces
    private StringBuffer prepareAttrListForParsing(String attrs)
    {
        StringBuffer sb = new StringBuffer(" " + attrs + " ");
        int imax = sb.length() -1;
        for (int i=0; i <= imax; i++)
        {
            if (sb.charAt(i) == '|' && i < imax && sb.charAt(i+1) == '|') {
                sb.setCharAt(i, ' ');
                sb.setCharAt(i+1, ' ');
            }
        }
        return sb;
    }

    // Check if the parsing list == "*"
    private boolean isAllAttrsWildcard(StringBuffer sb)
    {
        int idx = -1, cnt = 0; // searching for '*'

        for (int i=0; i < sb.length(); i++)
        {
            if (sb.charAt(i) == '*') {
                idx = i;
                cnt++;
            }
            else if (sb.charAt(i) != ' ') {
                return false;
            }
        }
        if (cnt==1) {
            sb.setCharAt(idx, ' ');
            return true;
        }
        return false;
    }

    // Find an attribute in the parsing list and remove it from the list
    private boolean hasAttr(StringBuffer attrList, String attr)
    {
        int idx = attrList.toString().indexOf(" " + attr.toLowerCase() + " ");
        if (idx >= 0) {
            for (int i=0; i < attr.length(); i++) {
                int modIdx = idx + 1 + i;
                attrList.setCharAt(modIdx, ' ');
            }
            return true;
        }
        return false;
    }

    // At the end of processing the list should contain only blancs
    private boolean isEmptyAttrList(StringBuffer attrList)
    {
        for (int i=0; i < attrList.length(); i++)
        {
            if (attrList.charAt(i) != ' ') {
                Debug.println("ACI TargetTab: can not process the whole attr list: " + attrList);
                return false;
            }
        }
        return true;
    }

    private synchronized void updateAttributeTable() throws Exception
    {
        DefaultTableModel tm = attrTableModel;
        if(tm == null)
            return;

        StringBuffer attrList = prepareAttrListForParsing(selectedACIAttrs.toLowerCase());

        int rowCount = tm.getRowCount();
        String attrName;
        boolean equality = targetAttrEquality.equals("=");
        boolean allAttrs = isAllAttrsWildcard(attrList);
        boolean newState;
        Boolean oldState;
        for(int i = 0; i < rowCount; i++)
        {
            newState = equality;
            attrName = (String)tm.getValueAt(i, 1);
            if(!allAttrs)
            {
                if(!hasAttr(attrList, attrName))
                    newState = !equality;
            }
            oldState = (Boolean)tm.getValueAt(i, 0);
            if(oldState.booleanValue() != newState)
                tm.setValueAt(Boolean.valueOf(newState), i, 0);
        }
        if (!isEmptyAttrList(attrList)) // list completely processed?
        {
            throw new Exception(i18n("attrListErr"));
        }
        tm.fireTableDataChanged();
    }

    private void setAttrEditingEnabled(boolean enable)
    {
        noneButton.setEnabled(enable);
        allButton.setEnabled(enable);
        attrTable.setEnabled(enable);
        attrTable.setBackground((enable ? UIManager.getColor("window") :
                                          UIManager.getColor("control")));
    }

    private void populateAttributeTable()
    {
        DefaultTableModel tm = attrTableModel;
        int count = 0;
        Enumeration e = schema.getAttributes();
        while(e.hasMoreElements())
        {
          LDAPAttributeSchema attr = (LDAPAttributeSchema)e.nextElement();
          tm.addRow(new Object[] { Boolean.valueOf(false), attr.getName(), attr.getOID() });
          if(count++ == 100)
          {
              count = 0;
              tm.newRowsAdded(new TableModelEvent(tm, 0, tm.getRowCount()-1, TableModelEvent.ALL_COLUMNS, TableModelEvent.INSERT));
          }
        }
        tm.newRowsAdded(new TableModelEvent(tm, 0, tm.getRowCount()-1, TableModelEvent.ALL_COLUMNS, TableModelEvent.INSERT));
    }

    class SchemaThread extends Thread
    {
        LDAPConnection ldc;

        public SchemaThread(LDAPConnection ldc)
        {
            this.ldc = ldc;
            setPriority(Thread.MIN_PRIORITY);
        }

        public void run()
        {
            attrTable.setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
            setAttrEditingEnabled(false);
            try
            {
                if(schema == null)
                {
                    schema = new LDAPSchema();
                    schema.fetchSchema(ldc);
                }

                if(attrTableModel.getRowCount() == 0)
                    populateAttributeTable();

                try {
                    updateAttributeTable();
                }
                catch (Exception e) {
                    attrTable.setCursor(Cursor.getDefaultCursor());
                    final Container parent = SwingUtilities.getAncestorOfClass(JDialog.class, attrTable);
                    final String msg = i18n("attrListErr");
                    final String title = i18n.getString("ed", "visualFailedTitle");
                    SwingUtilities.invokeLater( new Runnable () {
                        public void run() {
                            JOptionPane.showMessageDialog(
                                parent, msg, title, JOptionPane.ERROR_MESSAGE);
                        }
                    });
                    return;
                }

            }
            catch(LDAPException e)
            {
                schema = null;
                System.err.println("ACI TargetTab: unable to read schema\nException: " + e);
            }
            setAttrEditingEnabled(true);
            attrTable.setCursor(Cursor.getDefaultCursor());
        }
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
        int rowCount = attrTableModel.getRowCount();
        for(int i = 0; i < rowCount; i++)
        {
            attrTableModel.setValueAt(Boolean.valueOf(state), i, 0);
        }
        attrTableModel.fireTableDataChanged();
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
                new ACIAttribute(KEYWORD_TARGETENTRY, "=|!=", "\"" + BIND_PREFIX + " \""),
                new ACIAttribute(KEYWORD_TARGETFILTER, "=|!=", "\" \""),
                new ACIAttribute(KEYWORD_TARGETATTRS, "=|!=", "\" \"") // TODO: use tighter syntax
            };
    }
}
