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
package com.netscape.management.client.topology;

import java.awt.event.*;
import javax.swing.*;
import com.netscape.management.client.*;
import com.netscape.management.client.console.*;
import com.netscape.management.client.util.*;
import netscape.ldap.*;

/**
 * TopologyModel defined the topology view tree model.
 *
 * @author   terencek
 * @version  %I%, %G%
 */

public class TopologyModel extends ResourceModel implements IMenuInfo {

    static ResourceSet _resource = new ResourceSet("com.netscape.management.client.topology.topology");
    static String MENU_NEW_DOMAIN = "newDomain";
    static String MENU_REMOVE_DOMAIN = "removeDomain";
//    static String MENU_ADD_SERVER = "addServer";
//    static String MENU_REMOVE_SERVER = "removeServer";
    static String MENU_REFRESH = "refresh";
    //static String MENU_CERTMGT = "certmgt";
    private boolean canEditTopology = true;

    // The following data members are initialized in the constructor.
    ConsoleInfo _consoleInfo;
    IResourceObject[]_selection;

    //protected CertManagementDialog manageCert = null;

    // private boolean _firstIResourceModelListener;  // TODO: why is this necessary?  -ahakim

    /**
     * Creates a new TopologyModel.
     *
     * @param info global information block
     */
    public TopologyModel(ConsoleInfo info, boolean canEditTopology) {
        _consoleInfo = info;
        this.canEditTopology = canEditTopology;
        _selection = null;
        /*StatusThread statusThread = new StatusThread(this);
         statusThread.start();
         info.put("statusThread", statusThread);*/
        setRoot(new TopTopologyNode());
    }



    /**
      * Notification that objects were selected in the resource tree.
      */
    void updateStatusBar(IResourceObject node) {
    }



    /**
      * Notification that objects were selected in the resource tree.
      */
    public void serverStateChanged(ServerNode server) {

        // TODO: add support for multiple selection
        if ((_selection != null) && (_selection[0] == server)) {
            updateStatusBar(server);
            nodeChanged(server);
        }
    }



    /**
      * Adds a listener that is interested in receiving IResourceModelListener.
      * Called by ResourcePage
      */
    public void addIResourceModelListener(IResourceModelListener l) {
        super.addIResourceModelListener(l);
    }



    /**
      * Removes a listener that is interested in receiving IResourceModelListener.
      * Called by ResourcePage
      */
    public void removeIResourceModelListener(IResourceModelListener l) {

        super.removeIResourceModelListener(l);
    }



    /**
      * Returns menu categories for this model.
      */
    public String[] getMenuCategoryIDs() {
        return new String[]{ Framework.MENU_FILE, //Framework.MENU_FILENEW, // 120987
            Framework.MENU_VIEW };
    }



    /**
      * Returns menu items for this model.
      */
    public IMenuItem[] getMenuItems(String category) {
        IMenuItem iReturn[] = null;
        /*
         if (category.equals(Framework.MENU_FILENEW)) // 120987
         {
         	iReturn = new IMenuItem[]
         	{
         		new MenuItemText(MENU_NEW_DOMAIN, _resource.getString("menu", "newDomain"), "TODO: description"),
         	};
         }
         else
         */
        if (category.equals(Framework.MENU_FILE)) {

            if(canEditTopology)
            {
                iReturn = new IMenuItem[]{ new MenuItemText(MENU_NEW_DOMAIN,
                        _resource.getString("menu", "newDomain"),
                         "TODO: description"), 
                 new MenuItemText(MENU_REMOVE_DOMAIN,
                         _resource.getString("menu", "RemoveDomain"),
                         "TODO: description"), 
                 new MenuItemSeparator()};
            }
        } else if (category.equals(Framework.MENU_VIEW)) {
            MenuItemText menuItemText = new MenuItemText(MENU_REFRESH, 
                     _resource.getString("menu", "refresh"), "TODO: description"); 
                     menuItemText.setAccelerator(KeyStroke.getKeyStroke(KeyEvent.VK_R, 
                               ActionEvent.CTRL_MASK)); 
             iReturn = new IMenuItem[]{ new MenuItemSeparator(), menuItemText}; 
        }
        return iReturn;
    }

    /**
      * Notification that one or more objects were selected.
      */
    public void actionObjectSelected(IPage viewInstance,
            IResourceObject[] selection,
            IResourceObject[] previousSelection) {
        super.actionObjectSelected(viewInstance, selection,
                previousSelection);
        _selection = selection; // save this so you know which object to apply menu action to

        if (_selection != null) {
            if (selection[0] instanceof DomainNode && selection.length == 1) {
               DomainNode dn = (DomainNode)_selection[0];
               fireEnableMenuItem(viewInstance, MENU_REMOVE_DOMAIN);
            }
            else
               fireDisableMenuItem(viewInstance, MENU_REMOVE_DOMAIN);

            updateStatusBar(selection[0]);

            if (_selection.length == 1) {
                updateStatusBar(selection[0]);
            } else // multiple selection
            {
                fireChangeStatusItemState(null, Framework.STATUS_TEXT, "");
            }
        }
        else {
            fireDisableMenuItem(viewInstance, MENU_REMOVE_DOMAIN);
        }

    }


    /**
      * Notification that a menu item has been selected.
      */
    public void actionMenuSelected(IPage viewInstance, IMenuItem item) {
        if (item.getID().equals(MENU_NEW_DOMAIN)) {
            NewDomainDialog d = new NewDomainDialog(null, _consoleInfo);
            d.show();
            refreshTree(viewInstance);
        } else if (item.getID().equals(MENU_REMOVE_DOMAIN)) {
            if (_selection[0] instanceof DomainNode) {
                removeDomain(viewInstance, (DomainNode)_selection[0]);
                refreshTree(viewInstance);
            }
        /*} else if (item.getID().equals(MENU_CERTMGT)) {
            if (manageCert == null) {
                manageCert = new CertManagementDialog();
            } else {
                manageCert.show();
            }*/
        }
        if (item.getID().equals(MENU_REFRESH)) {
            refreshTree(viewInstance);
            ((TopologyResourcePage) viewInstance).refresh();
        }
		
    }

    /**
      * refresh the topology tree
      *
      * @param viewInstance topology view instance
      */
    public void refreshTree(IPage viewInstance) {
        ResourceObject root = (ResourceObject) getRoot();
        if (root instanceof TopTopologyNode) {
            TopTopologyNode topNode = (TopTopologyNode) root;
            topNode.reload();
        }
        fireTreeStructureChanged(root);
        expandFirstNode(viewInstance);
    }

    /**
      * expand the first node
      *
      * @param viewInstance topology console instance
      */
    private void expandFirstNode(IPage viewInstance) {
        ResourceObject root = (ResourceObject) getRoot();
        if (!root.isLeaf() && (root.getChildCount() > 0)) {
            ResourceObject firstChild = (ResourceObject) getChild(root, 0);
            if (firstChild instanceof DomainNode)
                fireExpandTreeNode(viewInstance,
                        (ResourceObject) firstChild);
        }
    }
    
    /**
     * Removes domain node.  It it contains children, 
     * an error message is displayed.
     */
    private void removeDomain(IPage viewInstance, DomainNode node)
    {
        JFrame frame = viewInstance.getFramework().getJFrame();
        String messageTemplate;
        String message;
        String title;
        LDAPConnection ldc = _consoleInfo.getLDAPConnection();

        if(hasHosts(ldc, node.getDN()))
        {
            messageTemplate = _resource.getString("RemoveDomain", "cannotMessage");
            message = java.text.MessageFormat.format(messageTemplate, new Object[] { node.getName() });
            title = _resource.getString("RemoveDomain", "cannotTitle");
            JOptionPane.showMessageDialog(frame, message, title, JOptionPane.ERROR_MESSAGE);
            return;
        }
        
        messageTemplate = _resource.getString("RemoveDomain", "message");
        message = java.text.MessageFormat.format(messageTemplate, new Object[] { node.getName() });
        title = _resource.getString("RemoveDomain", "title");
        int result = JOptionPane.showConfirmDialog(frame, message, title, JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE);
        if(result == JOptionPane.YES_OPTION)
        {
            try
            {
                deleteTree(ldc, node.getDN());
            }
            catch(LDAPException e)
            {
                messageTemplate = _resource.getString("RemoveDomain", "errorMessage");
                message = java.text.MessageFormat.format(messageTemplate, new Object[] { node.getName() });
                title = _resource.getString("RemoveDomain", "errorTitle");
                JOptionPane.showMessageDialog(frame, message, title, JOptionPane.ERROR_MESSAGE);
            }
        }
    }
     
    /**
     * Deletes the specified DN including any sub-entries.
     *
     * @param entry the dn to delete
     */
    void deleteTree(LDAPConnection ldc, String dn) throws LDAPException
    {
        Debug.println("deleteTree() " + dn);
        LDAPSearchResults search_results = null;
        String[] attrs = { "numsubordinates" };
        search_results = ldc.search(dn, LDAPConnection.SCOPE_ONE, "(objectClass=*)", attrs, false);
        while(search_results.hasMoreElements())  // recursively delete children
        {
            LDAPEntry entry = (LDAPEntry)search_results.nextElement();
            deleteTree(ldc, entry.getDN());
        }
        Debug.println("Deleting entry " + dn);
        ldc.delete(dn);
    }

 
    /**
     * Returns true if this entry contains nsHosts attributes.
     *
     * @param entry the dn to delete
     */
    boolean hasHosts(LDAPConnection ldc, String dn)
    {
        LDAPSearchResults search_results = null;
        String[] attrs = { "numsubordinates" };
        try
        {
            search_results = ldc.search(dn, LDAPConnection.SCOPE_ONE, "(objectClass=nsHost)", attrs, false);
            return search_results.hasMoreElements();
        }
        catch(LDAPException e)
        {
            return true;
        }
    }
    
    
}
