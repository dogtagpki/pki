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
package com.netscape.management.client.components;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.tree.*;
import java.awt.*;
import java.util.*;
import netscape.ldap.*;
import com.netscape.management.client.console.ConsoleHelp;
import com.netscape.management.client.util.*;

/**
 * DirBrowserDialog allows selection of an LDAP entry by browsing directory tree.
 * 
 * This dialog is intended to be used in the simple but common
 * case where a single directory entry selection is required.
 * 
 * The tree display mechanism is based on <code>DirTree</code>.
 * The large and wide ranging set of APIs available in DirTree
 * (and its superclass JTree) are not duplicated or selectively 
 * exposed here.  Instead, direct public access to the <code>dirTree</code> 
 * object is provided.  You can use it to customize the tree
 * behavior, enable multiple selection, and add various 
 * types of listeners.
 * 
 * @see com.netscape.management.client.components.DirTree
 * 
 * @author Andy Hakim
 * @author Thu Le
 */
public class DirBrowserDialog extends GenericDialog
{
    private LDAPConnection ldc = null;
    private String baseDN = null;
    private JPanel selectionPanel;
    private JTextField selectionField;
    
    /**
     * Renders tree data.  After construction, this object is
     * set with DefaultDirModel which is initialized with the
     * specified ldap connection and base dn.
     */
    public DirTree tree;
    
    private static ResourceSet resource = new ResourceSet("com.netscape.management.client.components.components");    

    private static String i18n(String id) 
    {
        return resource.getString("dirBrowser", id);
    }
    
    /**
     * Constructs a directory entry selection dialog with a directory tree
     * (no leaf shown and single selection only),
     * OK and Cancel button, and a detail area which shows the information of selected entry
     * The localized title "Select Directory Entry" is used.
     * 
     * @param parent the parent frame of the dialog
     * @param ldc the LDAPConnection
     */
    public DirBrowserDialog(JFrame parent, LDAPConnection ldc)
    {
        this(parent, i18n("title"), ldc, null);
    }

    /**
     * Constructs a directory entry selection dialog with a directory tree
     * (no leaf shown and single selection only),
     * OK and Cancel button, and a detail area which shows the information of selected entry
     * The localized title "Select Directory Entry" is used.
     * 
     * @param parent the parent frame of the dialog
     * @param ldc the LDAPConnection
     * @param baseDN base DN value
     */
    public DirBrowserDialog(JFrame parent, LDAPConnection ldc, String baseDN)
    {
    	this(parent, i18n("title"), ldc, baseDN);
	}
    
    /**
     * Constructs a directory entry selection dialog with a directory tree
     * (no leaf shown and single selection only),
     * OK and Cancel button, and a detail area which shows the information of selected entry
     * Need to call initialize()to populate the tree
     * 
     * @param parent the parent frame of the dialog
     * @param title the title for the dialog
     * @param ldc the LDAPConnection
     */
    public DirBrowserDialog(JFrame parent, String title, LDAPConnection ldc)
    {
        this(parent, title, ldc, null);
    }
    
    /**
     * Constructs a directory entry selection dialog with a directory tree
     * (no leaf shown and specified multi selection option),
     * OK, Cancel, and Help button, and a detail area which shows the information of selected entry
     * Need to call initialize()to poppulate the tree
     * 
     * @param parent the parent frame of the dialog
     * @param title the title for the dialog
     * @param ldc the LDAPConnection
     * @param baseDN base DN value
     */
    public DirBrowserDialog(JFrame parent, String title, LDAPConnection ldc, String baseDN)
    {
        super(parent, title);
        this.ldc = ldc;
        this.baseDN = baseDN;
        setOKButtonEnabled(false);
        getContentPane().add(createPanel());
        setMinimumSize(getContentPane().getPreferredSize());
    }
    
    /**
     * Creates the component panel for this dialog.
     * This method may be subclassed to extend the layout.
     * 
     * @return the panel containing all UI for this dialog
     */
    protected JPanel createPanel()
    {
        GridBagLayout gbl = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        JPanel panel = new JPanel();
        panel.setLayout(gbl);
        
        DirModel model = new DirModel(ldc);
        model.setShowsPrivateSuffixes(true);
        model.setAllowsLeafNodes(true);
        model.setReferralsEnabled(true);
        model.initialize((baseDN != null) ? new DirNode( model, baseDN) : null);
        
        tree = new DirTree(model) {
            public void expandPath(TreePath path)
            {
                setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
                super.expandPath(path);
                setCursor(Cursor.getDefaultCursor());
            }
        };

        tree.addDirNodeListener(new DirNodeListener());
        tree.addTreeSelectionListener(new TreeSelectionListener()
            {
                public void valueChanged(TreeSelectionEvent e)
                {
                    if (tree.isSelectionEmpty())
                    {
                        setOKButtonEnabled(false);
                        selectionField.setText("");
                    }
                    else 
                    {
                        setOKButtonEnabled(true);
                    }
                }
            });

        JScrollPane treeScrollPane = new JScrollPane(tree);
        JPanel treePanel = ComponentFactory.createLabelComponent(i18n("treeLabel"), treeScrollPane);
        
        gbc.gridx = 0;       gbc.gridy = 0;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 1.0;   gbc.weighty = 1.0;
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.fill = GridBagConstraints.BOTH;
        gbl.setConstraints(treePanel, gbc);
        panel.add(treePanel);

        selectionField = new JTextField("");
        selectionField.setEditable(false);
        selectionField.setBackground(UIManager.getColor("control"));
        
        selectionPanel = ComponentFactory.createLabelComponent(i18n("selectionField"), selectionField);
        selectionPanel.setBorder(BorderFactory.createEmptyBorder(COMPONENT_SPACE, 0, 0, 0));
        
        gbc.gridx = 0;       gbc.gridy = 1;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 1.0;   gbc.weighty = 0.0;
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbl.setConstraints(selectionPanel, gbc);
        panel.add(selectionPanel);
        panel.setPreferredSize(new Dimension(250, 300));

        return panel;
    }
    
    
    class DirNodeListener implements IDirNodeListener
    {
        /**
         * The selection changed.
         *
         * @param nodes Array of selected tree nodes
         */
        public void selectionChanged( IDirNode[] nodes ) 
        {
            if(nodes.length > 1)
            {
                selectionField.setText("multi-selected");
            }
            else 
            {
                StringTokenizer tokens = new StringTokenizer("" + nodes[0], "<");
                String token = "";
                // eliminates "<"
                if (tokens.hasMoreTokens()){
                    token = tokens.nextToken();
                }
                // eliminates ">"
                if (tokens.hasMoreTokens()){
                    token = tokens.nextToken();
                }
                tokens = new StringTokenizer(token,">");
                if (tokens.hasMoreTokens()){
                    token = tokens.nextToken();
                }
                if (token.equals(">")){
                    token = "";
                }
                selectionField.setText(token);
            }
        }

        /**
         * An action was invoked using the mouse or keyboard.
         *
         * @param ev Object indicating the type of event.
         */
        public void actionInvoked(DirNodeEvent ev)
        {
        }   
    }
    
    /**
     * Retreive directory tree model.
     * 
     * @return the directory tree model.
     */
    public IDirModel getDirModel()
    {
        return (IDirModel)tree.getModel();
    }
    
    /**
     * Sets new directory tree model.
     * 
     * @param model the directory tree model
     */
    public void setDirModel(IDirModel model)
    {
        tree.setModel(model);
    }
    
    /**
     * Sets the baseDN for the directory entry selection dialog
     * 
     * @param baseDN the value of the baseDN
     */
    public void setBaseDN(String baseDN)
    {
        this.baseDN = baseDN;
    }
    
    /**
     * Gets the current baseDN value
     *
     * @return the current baseDN value
     */
    public String getBaseDN()
    {
        return baseDN;
    }
     
    /**
     * Sets the LDAPConnection for directory entry selection dialog
     *
     * @param ldc the LDAPConnection object
     */
    public void setLDAPConnection(LDAPConnection ldc)
    {
        this.ldc = ldc;
    }
    
    /**
     * Gets the LDAPConnection of directory entry selection dialog
     *
     * @return the current LDAPConnection
     */
    public LDAPConnection getLDAPConnection()
    {
        return ldc;
    }
    
    /**
     * Sets the visibility of the selection field.
     * 
     * @param visibility the display state of the selection field.
     */
    public void setSelectionFieldVisible(boolean visibility)
    {
        selectionPanel.setVisible(visibility);
    }
    
    /**
     * Determines whether selection field is visible.
     * 
     * @return true if selection field is visible.
     */
    public boolean isSelectionFieldVisible()
    {
        return selectionPanel.isVisible();
    }
    
    /**
     * Returns the selected DN in the tree.
     * An empty string is returned if no value is selected.
     * 
     * @return the DN of the selected tree node.
     */
    public String getSelectedDN()
    {
        return selectionField.getText();
    }
   
    /**
     * Called when the Help button is pressed.
     * Displays pre-defined help content for this dialog.
     * If you extend this dialog and change its UI, 
     * you should also subclass this method and provide 
     * your own help content.
     */
    public void helpInvoked()
    {
        ConsoleHelp.showContextHelp("directoryBrowser");
    }
}
