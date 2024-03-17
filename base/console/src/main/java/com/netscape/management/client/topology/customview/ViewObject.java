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

import java.awt.*;
import javax.swing.*;
import com.netscape.management.client.*;
import com.netscape.management.client.topology.*;
import javax.swing.event.*;

/**
 * Visual representation of a CustomView as a folder. The CustomView is the "model"
 * while this ViewObject is the "view". If the CustomModel references a resource
 * (through seeAlso attribute in the view ldap entry), this ViewObject is then a
 *  wrapper for the corresponding ResourceObject. In that case the ViewObject controls
 * view name, icon and child objects. 
 */
class ViewObject extends ResourceObject implements IMenuInfo, INodeInfo{
    
    CustomView _view;
    IResourceObject _peerResource;
    NodeDataPanel _nodeDataPanel;
    NodeData _description;
    ImageIcon _largeIcon;
    
    private static String _descriptionText =
        TopologyInitializer._resource.getString("ServerObject", "description");
        
    /**
     * Constructor
     */
    public ViewObject(CustomView view) {
        this._view = view;
        initialize();
    }
    
    /**
     * Initialize view object from the CustomView. If the view references a
     * resource, the display name and icon specified with the view override
     * the ones provided by the resource.
     */
    void initialize() {
        _peerResource = _view.getResourceRef();
        if (_peerResource != null) {
            // For top-level nodes, displayName is the name of the view rather than
            // the root-node name. Use name and icon from the resource object
            if  (_view.getParentView() == null) { 
                setName(_peerResource.getName());                
                setIcon(_peerResource.getIcon());
            }
            // For non top level nodes, displayName/displayIcon override the
            // name/icon in the resource object
            else {
                setName(_view.getDisplayName());
                setIcon(_view.getDisplayIcon());
            }                
        }
        else {
            setName(_view.getDisplayName());
            setIcon(_view.getDisplayIcon());
            
            // Default RHP has only description field
            if (_view.getDescription() != null) {
                _description = new NodeData("id", _descriptionText, _view.getDescription());
            }
        }            
        
        if (getName() == null) {
            setName(_view.getID());
        }            

    }
    
    /**
     * Returns object that renders right hand panel contents
     * for this tree node.
     * @return a Component object that renders right hand panel contents
     */
    public Component getCustomPanel() {
        if (_peerResource != null) {
            return _peerResource.getCustomPanel();
        }
        if (_nodeDataPanel == null) {
            _nodeDataPanel = new NodeDataPanel(getIcon(), getName(),
                 this, false, false);
        }   
        return _nodeDataPanel;
    }       

    /**
     * Returns the large icon for this tree node.
     * The icon is created by scaling the regular icon to 32x32 size.
     * @return An icon of size 32x32
     */
    public Icon getLargeIcon() {
        Icon largeIcon = super.getLargeIcon();
        if (largeIcon == null) {
            ImageIcon icon = (ImageIcon) getIcon();
            Image largeImage = 
                icon.getImage().getScaledInstance(32,32,Image.SCALE_SMOOTH);
            setLargeIcon(largeIcon = new ImageIcon(largeImage));
        }
        return largeIcon;
    }                


    /**
     * implements IResourceObject
     * Notification that this node has been unselected in the tree.
     * @param viewInstance		IPage instance which calls this method
     */
    public void unselect(IPage viewInstance) {
        if (_peerResource != null) {
            _peerResource.unselect(viewInstance);
        }
        else {
            super.unselect(viewInstance);
        }            
    }

    /**
     * Notification that this node has been selected in the tree.
     * @param viewInstance		IPage instance which calls this method
     */
     public void select(IPage viewInstance) {
        if (_peerResource != null) {
            _peerResource.select(viewInstance);
        }
        else {
            super.select(viewInstance);
        }
    }

    /**
     * Notification that this object needs to execute an action.
     * Called when user double clicks on a tree node.  For example, called when
     * user drills down to server instance, then double-clicks on it to launch
     * Server window.
     *
     * @param viewInstance		IPage instance which calls this method
     * @return boolean value indicating whether run action completed succesfully
     */
    public boolean run(IPage viewInstance, IResourceObject selection[]) {
        if (_peerResource != null) {
            return _peerResource.run(viewInstance, selection);
        }
        else {
            return super.run(viewInstance, selection);
        }
    }

    /**
     * An inquiry about whether this object can execute 'run' action
     * on behalf all the multiple selected objects in tree.
     * If return is true, the run method will be called (only on this node)
     * @param selection			array of IResourceObjects currently selected in tree
     * @return boolean value indicating whether object can execute 'run' method
     */
    public boolean canRunSelection(IResourceObject selection[]) {
        if (_peerResource != null) {
            return _peerResource.canRunSelection(selection);
        }
        else {
            return super.canRunSelection(selection);
        }
    }
    /**
      * return the menu category
      *
      * @return list of affect menu categories
      */
    public String[] getMenuCategoryIDs() {
        if (_peerResource != null && _peerResource instanceof IMenuInfo) {
            return ((IMenuInfo)_peerResource).getMenuCategoryIDs();
        }
        return null; //new String[0];
    }


    /**
      * return a list of menu item for the given category
      *
      * @param category menu category
      * @return the menu item for the given category
      */
    public IMenuItem[] getMenuItems(String category) {
        if (_peerResource != null && _peerResource instanceof IMenuInfo) {
            return ((IMenuInfo)_peerResource).getMenuItems(category);
        }
        return null;
    }

    /**
      * perform action for the menu item
      *
      * @param viewInstance view instance of the console
      * @param item menu item which is selected
      */
    public void actionMenuSelected(IPage viewInstance, IMenuItem item) {
        if (_peerResource != null && _peerResource instanceof IMenuInfo) {
            ((IMenuInfo)_peerResource).actionMenuSelected(viewInstance, item);
        }
    }
   
    /**
     * INodeInfo interface implementatioin
     */    
    public int getNodeDataCount() {
        return _view.getDescription() != null ? 1 : 0;
    }              
    public NodeData getNodeData(int index) {
        return _description;
    }                           
    public void actionNodeDataChanged(NodeData data) {}
    public void addChangeListener(ChangeListener e) {}
    public void removeChangeListener(ChangeListener e) {}
}