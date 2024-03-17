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
package com.netscape.management.client.topology.customview;

import java.util.*;
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.event.*;
import javax.swing.tree.*;
import javax.swing.table.*;
import com.netscape.management.client.topology.*;
import com.netscape.management.client.console.*;
import com.netscape.management.client.util.*;
import com.netscape.management.client.components.*;
import com.netscape.management.client.ace.*;
import netscape.ldap.*;

/**
 * custom view configuration dialog
 */
public class ViewSelectorDialog extends GenericDialog
{
    JFrame frame;
    Table table;
    DefaultTableModel tableModel;
    JButton newButton;
    JButton editButton;
    JButton deleteButton;
    JButton aclButton;
    Vector viewInfoVector;
    TreeModel defaultTreeModel;
    LDAPConnection ldc;
    String privateViewDN;
    String publicViewDN;
    ConsoleInfo consoleInfo;
	EditDialog editDialog = null;
    static String VIEW_PREFIX = "view";

    static String i18n(String id) {
        return TopologyInitializer._resource.getString("customview", id);
    }
    
    /**
      * custom view configuration dialog
      *
      * @param frame parent frame
      * @param viewInfoVector list of custom views
      * @param defaultTreeModel The default topology tree model
      * @param ldc LDAP Connection to the configuration directory server
      * @param privateViewDN DN of the custom view information
      * @param info console Information block
      */
    public ViewSelectorDialog(JFrame frame, Vector viewInfoVector,
            TreeModel defaultTreeModel, LDAPConnection ldc,
            String privateViewDN, String publicViewDN, ConsoleInfo info) {
        super(frame, "", CLOSE | HELP, HORIZONTAL);
        setTitle(i18n("title"));
        newButton = JButtonFactory.create(i18n("new"),new NewActionListener(),"NEW");
        newButton.setToolTipText(i18n("new_tt"));
        editButton = JButtonFactory.create(i18n("edit"),new EditActionListener(),"EDIT");
        editButton.setToolTipText(i18n("edit_tt"));
        deleteButton = JButtonFactory.create(i18n("delete"),new DeleteActionListener(),"DELETE");
        deleteButton.setToolTipText(i18n("delete_tt"));
        aclButton = JButtonFactory.create(i18n("access"),new AclActionListener(),"ACCESS");
        aclButton.setToolTipText(i18n("access_tt"));
        this.frame = frame;
        this.consoleInfo = info;
        this.defaultTreeModel = defaultTreeModel;
        this.ldc = ldc;
        this.privateViewDN = privateViewDN;
        this.publicViewDN = publicViewDN;
        this.viewInfoVector = viewInfoVector;
        getContentPane().add(createDialogPanel());
    }

    private JPanel createDialogPanel() {
        JPanel panel = new JPanel();

        GridBagLayout gridbag = new GridBagLayout();
        panel.setLayout(gridbag);
        GridBagConstraints c = new GridBagConstraints();

        tableModel = new DefaultTableModel()
            {
                public boolean isCellEditable(int row, int column)
                {
                    return false;
                }
            };
        tableModel.addColumn(i18n("columnName"));
        tableModel.addColumn(i18n("columnVisibility"));
        table = new Table(tableModel, true);
        table.setToolTipText(i18n("table_tt"));
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.getSelectionModel().addListSelectionListener(new ListSelectionListener()
            {
                public void valueChanged(ListSelectionEvent e) {
                    enableButtons();
                }
            });
        Enumeration e = viewInfoVector.elements();
        while (e.hasMoreElements()) {
            ViewInfo vi = (ViewInfo) e.nextElement();
            ICustomView customView = vi.getClassInstance();
            // skip non CustomView objects
            if (customView instanceof CustomView) {
                // skip system views (non-user views)
                if (((CustomView)customView).isSystemView()) {
                    continue;
                }
                tableModel.addRow(new Object[] { vi, getVisibilityString(vi.isPublic()) });
            }
        }
        enableButtons();

        c.gridx = 0;       c.gridy = 0;
        c.gridwidth = 1;   c.gridheight = 1;
        c.weightx = 1.0;   c.weighty = 1.0;
        c.fill = GridBagConstraints.BOTH;
		JScrollPane sp = new JScrollPane(table);
        gridbag.setConstraints(sp, c);
        panel.add(sp);

        Component viewButtonPanel = createViewButtonPanel();
        c.gridx = 1;        c.gridy = 0;
        c.gridwidth = 1;    c.gridheight = 1;
        c.weightx = 0.0;    c.weighty = 0.0;
        c.fill = GridBagConstraints.NONE;
        c.anchor = GridBagConstraints.NORTH;
        gridbag.setConstraints(viewButtonPanel, c);
        panel.add(viewButtonPanel);
        
        panel.setPreferredSize(new Dimension(400, 200));

        return panel;
    }
    
    private String getVisibilityString(boolean isPublic)
    {
        return (isPublic) ? i18n("public") : i18n("private");
    }
    

    /**
      * enable or disable buttons
      */
    private void enableButtons() {
        boolean enable = tableModel.getRowCount() > 0;
        ListSelectionModel lsm = table.getSelectionModel();
        if (enable && lsm.isSelectionEmpty()) {
            lsm.setSelectionInterval(0, 0);
        }
        
        editButton.setEnabled(enable);
        deleteButton.setEnabled(enable);
        
		int index = table.getSelectedRow();
        if(index == -1)
            enable = false;
        else
        {
            ViewInfo vi = (ViewInfo)tableModel.getValueAt(index, 0);
            enable = vi.isPublic();
        }
        aclButton.setEnabled(enable);
    }

    /**
      * create all the buttons
      */
    protected Component createViewButtonPanel() {
        JPanel panel = new JPanel();

        GridBagLayout gbl = new GridBagLayout();
        panel.setLayout(gbl);
        panel.setBorder(BorderFactory.createEmptyBorder(0, DIFFERENT_COMPONENT_SPACE, COMPONENT_SPACE, 0));
        GridBagConstraints c = new GridBagConstraints();

        c.gridwidth = 1;    c.gridheight = 1;
        c.gridx = 0;        c.gridy = 0;
        c.weightx = 1.0;    c.weighty = 1.0;
        c.fill = GridBagConstraints.HORIZONTAL;
        gbl.setConstraints(newButton, c);
        panel.add(newButton);

        c.gridwidth = 1;    c.gridheight = 1;
        c.gridx = 0;        c.gridy = GridBagConstraints.RELATIVE;
        c.weightx = 1.0;    c.weighty = 1.0;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.insets = new Insets(COMPONENT_SPACE, 0, 0, 0);
        gbl.setConstraints(editButton, c);
        panel.add(editButton);

        c.gridwidth = 1;    c.gridheight = 1;
        c.gridx = 0;        c.gridy = GridBagConstraints.RELATIVE;
        c.weightx = 1.0;    c.weighty = 1.0;
        c.fill = GridBagConstraints.HORIZONTAL;
        gbl.setConstraints(deleteButton, c);
        panel.add(deleteButton);
        
        c.gridwidth = 1;    c.gridheight = 1;
        c.gridx = 0;        c.gridy = GridBagConstraints.RELATIVE;
        c.weightx = 1.0;    c.weighty = 1.0;
        c.fill = GridBagConstraints.HORIZONTAL;
        gbl.setConstraints(aclButton, c);
        panel.add(aclButton);

        return panel;
    }

    /**
      * delete a custom view
      *
      * @param vi custom view information
      */
    private void deleteView(ViewInfo vi) {
        try {
            String dn = getViewDN(vi);
            ldc.delete(dn);
        } catch (LDAPException e) {
            Debug.println("LDAPException: return code:" +
                    e.getLDAPResultCode());
        }
    }

    /**
      * rename a custom view
      *
      * @param vi custom view information
      * @param newDisplayName new display name
      */
    private void renameView(ViewInfo vi, String newDisplayName) {
        try {
            String dn = getViewDN(vi);
            LDAPAttribute attr =
                    new LDAPAttribute("nsDisplayName", newDisplayName);
            LDAPModification modification =
                    new LDAPModification(LDAPModification.REPLACE, attr);
            ldc.modify(dn, modification);
        } catch (LDAPException e) {
            Debug.println("LDAPException: return code:" +
                    e.getLDAPResultCode());
        }
    }

    /**
      * add a new view
      *
      * @param vi custom view information
      * @param displayName display name of the custom view
      * @param className the associated java class name
      * @return true if view was successfully added
      */
    private boolean addView(ViewInfo vi) {
        try {
            String dn = getViewDN(vi);
            LDAPAttribute attr1 = new LDAPAttribute("cn", vi.getID());
            LDAPAttribute attr2 = new LDAPAttribute("objectclass", "nsCustomView");
            LDAPAttribute attr3 = new LDAPAttribute("objectclass", "nsTopologyCustomView");
            LDAPAttribute attr4 =
                    new LDAPAttribute("nsClassName", vi.getClassName());
            LDAPAttribute attr5 = new LDAPAttribute("nsDisplayName",
                    vi.getDisplayName());
            LDAPAttribute attr6 =
                    new LDAPAttribute("nsViewConfiguration", "<none>");
            LDAPAttributeSet attrs = new LDAPAttributeSet();
            attrs.add(attr1);
            attrs.add(attr2);
            attrs.add(attr3);
            attrs.add(attr4);
            attrs.add(attr5);
            attrs.add(attr6);
            LDAPEntry entry = new LDAPEntry(dn, attrs);
            ldc.add(entry);
            vi.setLdapEntry(entry);
        }
        catch (LDAPException e) 
        {
            int resultCode = e.getLDAPResultCode();
            Debug.println("LDAPException: return code:" + resultCode);
            if(resultCode == LDAPException.INSUFFICIENT_ACCESS_RIGHTS)
                JOptionPane.showMessageDialog(frame, i18n("InsufficientAccessMsg"), i18n("ViewCreateErrorTitle"), JOptionPane.ERROR_MESSAGE);
                
            return false;
        }
        return true;
    }
	
	private String getUniqueID(boolean isPublic)
	{
        String baseDN;
        if(isPublic)
            baseDN = publicViewDN;
        else
            baseDN = privateViewDN;

        int count = 1;
        while(true)
        {
            String dn = "cn=" + VIEW_PREFIX + Integer.toString(count) + "," + baseDN;
		    try
            {
		    	ldc.read(dn);
                count++;
		    } 
            catch (LDAPException e)
            {
		    	if (e.getLDAPResultCode() == LDAPException.NO_SUCH_OBJECT)
                {
                    return Integer.toString(count);
                }
                break;
		    }
        }
		return null;
	}
	
	private boolean isViewNameUsed(String viewName)
	{
		boolean isUsed = false;
        Enumeration e = viewInfoVector.elements();
        while (e.hasMoreElements()) 
        {
            ViewInfo vi = (ViewInfo) e.nextElement();
			if(vi.getDisplayName().equalsIgnoreCase(viewName))
			{
				isUsed = true;
				break;
			}
        }
        return isUsed;
	}	

    private String getViewDN(ViewInfo vi)
    {
        String baseDN;
        
        if(vi.isPublic())
            baseDN = publicViewDN;
        else
            baseDN = privateViewDN;
        
        return ("cn=" + vi.getID() + "," + baseDN);
    }
    
    
	/**
	 * displays the edit dialog
	 */
	private void showEditDialog(ViewInfo vi)
	{
		String oldName = vi.getDisplayName();
		ICustomView customView = vi.getClassInstance();
        String dn = getViewDN(vi);
        customView.initialize(ldc, dn);
        TreeModel customTreeModel = customView.getTreeModel();
        editDialog = new EditDialog(frame, defaultTreeModel,
						         customTreeModel, oldName);
		editDialog.setNameFieldFocused();
        editDialog.show();
		
        if (!editDialog.isCancel()) {
			String newName = editDialog.getViewName();
			customView.setTreeModel(customTreeModel); // save it in ldap
            if(!newName.equals(oldName))
            {
			    renameView(vi, newName);
                vi.setDisplayName(newName);
            }
        }
	}
    
    class AclActionListener implements ActionListener {
        public void actionPerformed(ActionEvent e) {
			int index = table.getSelectedRow();
            if(index != -1)
            {
                ViewInfo vi = (ViewInfo)tableModel.getValueAt(index, 0);
                String viewDN = getViewDN(vi);
                ACIManager acm = new ACIManager((JFrame)frame, vi.getDisplayName(), viewDN);
                acm.show();
            }
        }
    }

    class NewActionListener implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            
            VisibilityDialog visDialog = new VisibilityDialog(frame);
            visDialog.show();
			if(visDialog.isCancel())
                return;

            boolean isPublic = visDialog.isPublic();
            String name = i18n("newView");
            String id = getUniqueID(isPublic);
            if(id != null)
            {
                ViewInfo vi = new ViewInfo(VIEW_PREFIX + id, name + " " + id, "com.netscape.management.client.topology.customview.CustomView");
                vi.setPublic(isPublic);
                if(addView(vi))
                {
                    showEditDialog(vi);

                    if(!editDialog.isCancel())
                    {
                        viewInfoVector.addElement(vi);
                        tableModel.addRow(new Object[] { vi, getVisibilityString(vi.isPublic()) });
                        int index = table.getRowCount() - 1;
                        table.getSelectionModel().setSelectionInterval(index, index);
                        enableButtons();
                    }
                    else
                    {
                        deleteView(vi);
                    }
                }
            }
            else
            {
                Debug.println("Could not create unique view ID");
            }
        }
    }

    class EditActionListener implements ActionListener {
        public void actionPerformed(ActionEvent event) {
			int index = table.getSelectedRow();
            ViewInfo vi = (ViewInfo)tableModel.getValueAt(index, 0);
			
			showEditDialog(vi);
			if (!editDialog.isCancel())
			{
				viewInfoVector.removeElementAt(index);
				viewInfoVector.insertElementAt(vi,index);
				tableModel.removeRow(index);
                tableModel.insertRow(index, new Object[] { vi, getVisibilityString(vi.isPublic()) });
                table.getSelectionModel().setSelectionInterval(index, index);
			}
        }
    }

    class DeleteActionListener implements ActionListener {
        /**
          * confirm with the user about the delete operation
          */
        public void actionPerformed(ActionEvent e) {
            int index = table.getSelectedRow();
            if (index < 0)
                return;

            int value = JOptionPane.showConfirmDialog(
                    ViewSelectorDialog.this, i18n("removeConfirm"),
                    i18n("removeTitle"), JOptionPane.YES_NO_OPTION,
                    JOptionPane.QUESTION_MESSAGE);
            if (value == JOptionPane.YES_OPTION) {
                ViewInfo vi = (ViewInfo)viewInfoVector.elementAt(index);
                deleteView(vi);
                viewInfoVector.removeElementAt(index);
                tableModel.removeRow(index);

                if (index >= tableModel.getRowCount())
                    index--;

                if (tableModel.getRowCount() > 0)
                    table.getSelectionModel().setSelectionInterval(index, index);

                enableButtons();
            }
        }
    }

    /**
      * Called when HELP button is pressed
      */
    protected void helpInvoked() {
        Help help = new Help(TopologyInitializer._resource);
        help.contextHelp("customview", "ViewSelectorDialogHelp");
    }
}


class VisibilityDialog extends AbstractDialog
{
    JRadioButton privateLabel;
    JRadioButton publicLabel;
        
    static String i18n(String id) {
        return TopologyInitializer._resource.getString("VisibilityDialog", id);
    }
    
    public VisibilityDialog(Frame frame)
    {
        super(frame, "", true, OK | CANCEL | HELP);
        setTitle(i18n("title"));
        createDialogPanel();
        setDefaultButton(OK);
   }
    
    private void createDialogPanel() 
    {
        JPanel panel = new JPanel();

        GridBagLayout gridbag = new GridBagLayout();
        panel.setLayout(gridbag);
        GridBagConstraints c = new GridBagConstraints();

        JLabel headerLabel = new JLabel(i18n("header"));
        c.gridwidth = 1;   c.gridheight = 1;
        c.gridx = 0;       c.gridy = 0;
        c.weightx = 1.0;   c.weighty = 1.0;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.anchor = GridBagConstraints.NORTH;
        c.insets = new Insets(0, 0, COMPONENT_SPACE, 0);
        gridbag.setConstraints(headerLabel, c);
        panel.add(headerLabel);

        ButtonGroup radioGroup = new ButtonGroup();
        
        privateLabel = new JRadioButton(i18n("private"), true);
        c.gridx = 0;      c.gridy = GridBagConstraints.RELATIVE;
        c.weightx = 0.0;  c.weighty = 0.0;
        c.insets = new Insets(0, 3, 0, 0);
        gridbag.setConstraints(privateLabel, c);
        panel.add(privateLabel);
        setFocusComponent(privateLabel);

        publicLabel = new JRadioButton(i18n("public"));
        gridbag.setConstraints(publicLabel, c);
        panel.add(publicLabel);
        
        radioGroup.add(privateLabel);
        radioGroup.add(publicLabel);

        setComponent(panel);
    }
    
    public boolean isPublic()
    {
        return publicLabel.isSelected();
    }
    
    /**
      * Called when HELP button is pressed
      */
    protected void helpInvoked() {
		ConsoleHelp.showContextHelp("customview-ViewVisibility");
    }
}
