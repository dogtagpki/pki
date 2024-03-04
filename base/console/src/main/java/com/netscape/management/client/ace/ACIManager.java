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
import netscape.ldap.*;
import com.netscape.management.client.components.*;
import com.netscape.management.client.util.*;
import com.netscape.management.client.console.*;

/**
 * Access Control Manager dialog.  This is the entry point for 
 * creating/editing/removing access control on a directory entry.
 * 
 * Example usage:
 * 
 * ACIManager acm = new ACIManager(parentFrame, "Task Name", aciDN);
 * acm.show();
 * 
 * The above syntax will display a modal dialog
 * and edit the acis at the specified aciDN.
 * 
 * @see com.netscape.management.client.util.UtilConsoleGlobals.getActivatedFrame()
 * @see com.netscape.management.client.util.Console.getConsoleInfo().getLDAPConnection()
 * 
 */
public class ACIManager extends GenericDialog
{
    private static ResourceSet i18n = new ResourceSet("com.netscape.management.client.ace.ace");
    private static boolean showInheritedACIs = false;  // static to remember across invocations
    private JFrame parentFrame = null;
    private JButton newButton;
    private JButton editButton;
    private JButton removeButton;
	private String title;
	private IACITab[] tabs = null;
    private String ugDN;          // user and group DN
    private String aciDN;         // aci DN
    private Vector aciVector;     // collection of all ACIs affecting aciDN, ACI objects
    private JList aciList;
    private LDAPConnection aciLdc;
    private LDAPConnection ugLdc;
    private Vector extraACITabs = new Vector();
    private static final String ACL_PLUGIN_DN = "cn=ACL Plugin,cn=plugins,cn=config";
    
    private static String i18n(String id) 
    {
        return i18n.getString("mgr", id);
    }
    
    /**
     * Creates an ACIManager object with specified parameters.
     * The config ldap connection is obtained from ConsoleInfo.getLDAPConnection().
     * The user/group ldap connection is obtained from ConsoleInfo.getUserLdapConnection().
     * The user/group DN is obtained from ConsoleInfo.getUserGroupDN().
     * 
     * @param parentFrame   a JFrame object that will be the parent for this dialog.
     * @param title         a short, localized name describing this ACI
     * @param aciDN         a DN where ACIs reside
     */
    public ACIManager(JFrame parentFrame, String title, String aciDN)
    {
		this(parentFrame, title, Console.getConsoleInfo().getLDAPConnection(), aciDN, Console.getConsoleInfo().getUserLDAPConnection(), Console.getConsoleInfo().getUserBaseDN());
    }

    /**
     * Creates an ACIManager object with specified parameters.
     * 
     * @param parentFrame   a JFrame object that will be the parent for this dialog.
     * @param title         a short, localized name describing this ACI
     * @param aciLdc        a LDAP connection to server where ACIs reside
     * @param aciDN         a DN where ACIs reside
     * @param ugLdc         a LDAP connection to server where UGs reside
     * @param ugDN          a DN where Users and Groups reside
     */
    public ACIManager(JFrame parentFrame, String title, LDAPConnection aciLdc, String aciDN, LDAPConnection ugLdc, String ugDN)
    {
        super(parentFrame, "", OK_CANCEL_HELP, HORIZONTAL);
        this.parentFrame = parentFrame;
		this.title = title;
        this.aciLdc = aciLdc;
        this.ugLdc = ugLdc;
        this.aciDN = aciDN;
        this.ugDN = ugDN;
		String formattedTitle = java.text.MessageFormat.format(i18n("title"), new Object[] { title });
        setTitle(formattedTitle);
    }

    /**
     * Displays this dialog.  The dialog is modal; it blocks
     * access to other dialogs until it is dismissed.
     */
    public void show()
    {
        getContentPane().add(createContentPanel());
        super.show();
    }
    
    /**
     * Adds a tab to the list of tabs in the ACI Editor dialog.
     * 
     * @param tab the tab to add in the ACI Editor
     */
    public void addACIEditorTab(IACITab tab)
    {
        extraACITabs.addElement(tab);
    }
    
    /**
     * Removes a tab from the list of tabs in the ACI Editor dialog.
     * 
     * @param tab the tab to remove in the ACI Editor
     */
    public void removeACIEditorTab(IACITab tab)
    {
        extraACITabs.removeElement(tab);
    }
    
    private JPanel createContentPanel()
    {
        JPanel p = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();

        gbc.gridx = 0;       gbc.gridy = 0;
        gbc.gridwidth = 2;   gbc.gridheight = 1;
        gbc.weightx = 0.0;   gbc.weighty = 0.0;
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.insets = new Insets(0, 0, SEPARATED_COMPONENT_SPACE, 0);

        JTextArea infoLabel = new JTextArea();
        infoLabel.setPreferredSize(new Dimension(250, 48));
        infoLabel.setBackground(UIManager.getColor("control"));
        infoLabel.setText(i18n("info"));
        infoLabel.setLineWrap(true);
        infoLabel.setEditable(false);
        infoLabel.setWrapStyleWord(true);
        p.add(infoLabel, gbc);
        
        gbc.gridx = 0;       gbc.gridy = 1;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 1.0;   gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.insets = new Insets(0, 0, 0, 0);
        aciList = new JList(new DefaultListModel());
        aciList.setToolTipText(i18n("aci_tt"));
        aciList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        aciList.addListSelectionListener(new ListSelectionListener()
            {
                public void valueChanged(ListSelectionEvent e) {
                    enableButtons();
                }
            });
        JScrollPane sp = new JScrollPane(aciList);
        sp.setPreferredSize(new Dimension(300, 200));
        p.add(sp, gbc);

        gbc.gridx = 1;       gbc.gridy = 1;
        gbc.weightx = 0.0;   gbc.weighty = 0.0;
        gbc.fill = GridBagConstraints.NONE;
        gbc.anchor = GridBagConstraints.NORTHEAST;
        gbc.insets = new Insets(0, SEPARATED_COMPONENT_SPACE, 0, 0);
        JPanel buttonPanel = createButtonPanel();
        p.add(buttonPanel, gbc);
        
        JCheckBox cb = new JCheckBox(i18n("inherited"), showInheritedACIs);
        cb.addActionListener(new ActionListener()
            {
                public void actionPerformed(ActionEvent e)
                {
                    JCheckBox cbox = (JCheckBox)e.getSource();
                    showInheritedACIs = cbox.isSelected();
                    updateACIList(aciVector);
                }
            });
        setButtonComponent(cb);
        aciVector = new Vector();
        loadACIs(aciVector, aciDN, false);
        int length = aciDN.length();
        for(int i = 0; i < length; i++)
        {
            String dn;
            if(aciDN.charAt(i) == ',')
            {
                dn = aciDN.substring(i+1);
                loadACIs(aciVector, dn, true);
            }
        }
        updateACIList(aciVector);
		
        return p;
    }
    
    private void loadACIs(Vector aciVector, String aciDN, boolean isInherited)
    {
        Enumeration e = readACIsFromDN(aciDN);
        while(e.hasMoreElements())
        {
            ACI aci = new ACI((String)e.nextElement(), aciDN, isInherited, false/*modified*/);
            aciVector.addElement(aci);
        }
    }

    public static void testACI( LDAPConnection ldc, String DN, String aci) throws LDAPException
    {
        // Add the aci to the ACL plugin entry to verify if its syntax is correct.
        LDAPAttribute testACIAttr = new LDAPAttribute("aci");
        testACIAttr = new LDAPAttribute("aci");
        testACIAttr.addValue(aci);
        LDAPModification mod = null;

        try {
            mod = new LDAPModification(LDAPModification.ADD, testACIAttr);
            ldc.modify(DN, mod);

            mod = new LDAPModification(LDAPModification.DELETE, testACIAttr);
            ldc.modify(DN, mod);
        }
        catch (LDAPException e)
        {
            // We can ignore ATTRIBUTE_OR_VALUE_EXISTS as the aci was not changed
            if (e.getLDAPResultCode() != LDAPException.ATTRIBUTE_OR_VALUE_EXISTS){
                Debug.println("Failed to add/delete aci to testing entry: mod "
                    + mod.toString() + " - Error: " + e.getLDAPResultCode());
                Debug.println("Message: " + e.getLDAPErrorMessage());
                throw e;
            }
        }
    }
    
    private JPanel createButtonPanel()
    {
        JPanel p = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();

        gbc.gridx = 0;       gbc.gridy = GridBagConstraints.RELATIVE;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 1.0;   gbc.weighty = 1.0;
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.fill = GridBagConstraints.NONE;
        gbc.insets = new Insets(0, 0, COMPONENT_SPACE, 0);
        
        ActionListener buttonListener = new ButtonActionListener();
        
        newButton = ButtonFactory.createPredefinedButton(ButtonFactory.NEW, buttonListener);
        newButton.setToolTipText(i18n("new_tt"));
        p.add(newButton, gbc);
            
        editButton = ButtonFactory.createPredefinedButton(ButtonFactory.EDIT, buttonListener);
        editButton.setToolTipText(i18n("edit_tt"));
        p.add(editButton, gbc);
            
        removeButton = ButtonFactory.createPredefinedButton(ButtonFactory.REMOVE, buttonListener);
        removeButton.setToolTipText(i18n("remove_tt"));
        p.add(removeButton, gbc);

        ButtonFactory.resizeButtons(newButton, editButton, removeButton);
        enableButtons();
        
        return p;            
    }

    private void enableButtons() 
    {
        ListModel lm = aciList.getModel();
        boolean enable = lm.getSize() > 0;
        
        ListSelectionModel lsm = aciList.getSelectionModel();
        if(enable && lsm.isSelectionEmpty()) 
        {
            lsm.setSelectionInterval(0, 0);
        }
        
	Object aci = aciList.getSelectedValue();
	if ((aci != null) && ((ACI)(aci)).isInherited()) {
	    enable = false;
	}

        editButton.setEnabled(enable);
        removeButton.setEnabled(enable);
    }

    private void updateACIList(Vector aciVector)
    {
        DefaultListModel lm = (DefaultListModel)aciList.getModel();
        lm.removeAllElements();
        Enumeration e = aciVector.elements();
        while(e.hasMoreElements())
        {
            ACI aci = (ACI)e.nextElement();
            if(aci.isDeleted())
                continue;
            if(showInheritedACIs || (!showInheritedACIs && !aci.isInherited()))
                lm.addElement(aci);
        }
        enableButtons();
    }
    
    private void newACI()
    {
        ACIEditor ace = new ACIEditor(parentFrame, title, aciLdc, aciDN, ugLdc, ugDN, "");
        Enumeration e = extraACITabs.elements();
        while(e.hasMoreElements())
        {
            IACITab tab = (IACITab)e.nextElement();
            ace.addACITab(tab);
        }
        ace.show();
        if(!ace.isCancel())
        {
            ACI aci = new ACI(ace.getACI(), aciDN, false/*inherited*/, true/*modified*/);
            aci.setAdded(true);
            aciVector.addElement(aci);
            updateACIList(aciVector);
            ListSelectionModel lsm = aciList.getSelectionModel();
            ListModel lm = aciList.getModel();
            lsm.setLeadSelectionIndex(lm.getSize()-1);
        }
    }
    
    private void editACI()
    {
        ListSelectionModel lsm = aciList.getSelectionModel();
        int index = lsm.getLeadSelectionIndex();
        if(index >= 0)
        {
            ACI aci = (ACI)aciList.getSelectedValue();
            ACIEditor ace = new ACIEditor(parentFrame, title, aciLdc, aciDN, ugLdc, ugDN, aci.getData());
            Enumeration e = extraACITabs.elements();
            while(e.hasMoreElements())
            {
                IACITab tab = (IACITab)e.nextElement();
                ace.addACITab(tab);
            }
            ace.show();
            if(!ace.isCancel())
            {
                aci.setData(ace.getACI());
                aci.setModified(true);
                updateACIList(aciVector);
                lsm.setLeadSelectionIndex(index);
            }
        }
    }

    private void removeACI()
    {
        ListSelectionModel lsm = aciList.getSelectionModel();
        int index = lsm.getLeadSelectionIndex();
        if(index >= 0)
        {
            ACI aci = (ACI)aciList.getSelectedValue();
            String title = i18n("removeTitle");
            String msg = java.text.MessageFormat.format(i18n("removeMsg"), new Object[] { aci.getName() });
            int result = JOptionPane.showConfirmDialog(null, msg, title, JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE);
            if(result == JOptionPane.YES_OPTION)
            {
                aci.setDeleted(true);
                updateACIList(aciVector);
                ListModel lm = aciList.getModel();
                int rowCount = lm.getSize() -1;
                if(index >= rowCount)
                    index = rowCount;
                lsm.setLeadSelectionIndex(index);
            }
        }
    }

    class ButtonActionListener implements ActionListener
    {
        public void actionPerformed(ActionEvent e)
        {
            try {
                setBusyCursor(true);                
                String actionCommand = e.getActionCommand();
                if(actionCommand.equals(ButtonFactory.NEW))
                    newACI();
                else
                if(actionCommand.equals(ButtonFactory.EDIT))
                    editACI();
                else
                if(actionCommand.equals(ButtonFactory.REMOVE))
                    removeACI();
            }
            finally {
                setBusyCursor(false);
            }
        }
    }
    
	/**
	 * Called when the Help button is pressed.
	 */
    protected void helpInvoked()
	{
		ConsoleHelp.showContextHelp("ace-manager");
	}

    protected void okInvoked() 
	{
        try
        {
            writeACIsFromDN(aciDN, aciVector.elements());
            super.okInvoked();
        }
        catch(LDAPException e)
        {
            String title = i18n("errorTitle");
            String errorText = i18n("errorMsg");
            String tipText = i18n("errorTip"); 
            String extraInfo = e.getMatchedDN();
            String detailText = "LDAPException: " + e.errorCodeToString() +
                                " (" + e.getLDAPResultCode() +  ")\n" +
                                (extraInfo == null ? "" : extraInfo);
            ErrorDialog err = new ErrorDialog(this, title, errorText, tipText,
                   detailText, ErrorDialog.OK, ErrorDialog.OK);
            err.setVisible(true);
        }
    }

    private Enumeration readACIsFromDN(String dn)
    {
        LDAPSearchResults results = null;
        try 
        {
            results = aciLdc.search(dn, LDAPConnection.SCOPE_BASE, "(objectclass=*)", new String[] { "aci" }, false);
            while(results.hasMoreElements()) // should only be one entry because of SCOPE_BASE
            {
                LDAPEntry entry = (LDAPEntry)results.nextElement();
                LDAPAttributeSet attrSet = entry.getAttributeSet();
                Enumeration attributes = attrSet.getAttributes();
                while(attributes.hasMoreElements()) // should be only one attribute because of attr filter
                {
                    LDAPAttribute attr = (LDAPAttribute)attributes.nextElement();
                    return attr.getStringValues();
                }
            }
        }
        catch (LDAPException e)
        {
            Debug.println("Error reading ACI: " + e.getLDAPResultCode());
            Debug.println("Message: " + e.getLDAPErrorMessage());
            Debug.println("Matched DN: " + e.getMatchedDN());
        }
        return new Vector().elements();
    }

    private void writeACIsFromDN(String dn, Enumeration aciVector) throws LDAPException
    {
        ACI aci = null;
        try 
        {
            LDAPAttribute attr = new LDAPAttribute("aci");
            while(aciVector.hasMoreElements())
            {
                aci = (ACI)aciVector.nextElement();
                if(aci.getDN().equals(dn))
                {
                    if(aci.isDeleted() )
                    {
                        // Delete the original aci
                        String aciData = aci.getOrigData();
                        attr.addValue(aciData);
                        LDAPModification mod = new LDAPModification(LDAPModification.DELETE, attr);
                        aciLdc.modify(dn, mod);
                    }
                    else if(aci.isModified())
                    {
                        String origData = aci.getOrigData();
                        String currData = aci.getData();

                        // First check that entry has actually changed, or it's a new aci.
                        if(aci.isAdded() || !origData.equals(currData)){
                            String aciData = aci.getOrigData();
                            LDAPModification mod;

                            // Test the syntax before make update the aci
                            testACI(aciLdc, dn, currData);
                            attr.addValue(aciData);
                            if(!aci.isAdded())
                            {
                                // Delete the original aci first
                                mod = new LDAPModification(LDAPModification.DELETE, attr);
                                aciLdc.modify(dn, mod);
                            }

                            // Add the new/modified aci
                            attr.removeValue(aciData);
                            aciData = aci.getData();
                            attr.addValue(aciData);
                            mod = new LDAPModification(LDAPModification.ADD, attr);
                            aciLdc.modify(dn, mod);
                        }
                    }
                }
            }
        }
        catch (LDAPException e)
        {
            Debug.println("ACI Write Error: " + e.getLDAPResultCode());
            Debug.println("Message: " + e.getLDAPErrorMessage());
            throw e;
        }
    }
    
    class ACI
    {
        String dn;
        String data;
        String orig_data;
        String name;
        boolean isInherited = false;
        boolean isModified = false;
        boolean isDeleted = false;
        boolean isAdded = false;
    
        ACI(String data, String dn, boolean isInherited, boolean isModified)
        {
            this.dn = dn;
            this.isInherited = isInherited;
            setData(data);
            this.orig_data = new String(data);
            setModified(isModified);
        }
        
        public void setName(String name)
        {
            this.name = name;
        }
        
        public String getName()
        {
            if(name == null || name.length() == 0)
                return i18n("nonameACI");
            return name;
        }
        
        public String getData()
        {
            return data;
        }
        
        public String getOrigData()
        {
            return orig_data;
        }

        public void setData(String data)
        {
            this.data = data;

            ACIAttribute a = ACIAttribute.getAttribute("acl", ACIAttribute.toArray(ACIParser.getACIAttributes(data)));
            
            //bug 516529 : need to accept either acl or aci for the name
            if (a==null) {
                a = ACIAttribute.getAttribute("aci", ACIAttribute.toArray(ACIParser.getACIAttributes(data)));
            }

            if(a != null)
            {
                setName(a.getValue());
            }
        }
        
        public String getDN()
        {
            return dn;
        }
        
        public boolean isInherited()
        {
            return isInherited;
        }
        
        public boolean isModified()
        {
            return isModified;
        }
        
        public void setModified(boolean isModified)
        {
            this.isModified = isModified;
        }
        
        public boolean isDeleted()
        {
            return isDeleted;
        }
        
        public boolean isAdded()
        {
            return isAdded;
        }

        public void setDeleted(boolean isDeleted)
        {
            this.isDeleted = isDeleted;
            setModified(true);
        }

        public void setAdded(boolean isAdded)
        {
            this.isAdded = isAdded;
            setModified(true);
        }

        public String toString()
        {
            if(isInherited)
                return getName() + " " + i18n("inheritedACI");
            return getName();
        }
    }
}
