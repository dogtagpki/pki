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
package com.netscape.management.client;

import java.awt.*;
import javax.swing.*;
import javax.swing.tree.*;
import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;

/**
 * Implements properties and functionality of a tree node
 * of a ResourcePage tab in Console.
 *
 * A subclass of this object can optionally implement the
 * IMenuInfo interface to populate menu items in the Console window.
 *
 * This class is responsible for:
 * - having properties of a tree node
 * - receiving event notifications
 *
 * @see IResourceObject
 */
public class ResourceObject extends DefaultMutableTreeNode implements IResourceObject {
    String _name;
    Icon _icon = null;
    Icon _largeIcon = null;
    static ResourceSet resource = new ResourceSet("com.netscape.management.client.default");

    /**
     *    Creates empty resource object.
     */
    public ResourceObject() {
    }

    /**
     *    Creates resource object with specified name.
     */
    public ResourceObject(String sDisplayName) {
        this();
        _name = sDisplayName;
    }

    /**
     *    Creates resource object with specified name and icon.
     */
    public ResourceObject(String sDisplayName, Icon icon, Icon largeIcon) {
        this(sDisplayName);
        setIcon(icon);
        setLargeIcon(largeIcon);
    }

    public String toString() {
        return getName();
    }

    /**
     * Returns name that is displayed in tree view.
     * Called by: ResourceModel
     */
    public String getName() {
        return _name;
    }

    /**
     *    Sets name for this resource object.
     */
    public void setName(String name) {
        _name = name;
    }

    /**
     * Returns 16x16 icon that is displayed by each tree node.
     * Called by: ResourceModel
     */
    public Icon getIcon() {
        return _icon;
    }

    /**
     * Sets 16x16 icon that is displayed by each tree node.
     */
    public void setIcon(Icon icon) {
        _icon = icon;
    }

    /**
     * Returns 32x32 icon that is displayed by each tree node.
     * Called by: ResourceModel
     */
    public Icon getLargeIcon() {
        return _largeIcon;
    }

    /**
     * Sets 32x32 icon that is displayed by each tree node.
     */
    public void setLargeIcon(Icon icon) {
        _largeIcon = icon;
    }

    /**
     * Returns the AWT Component that is displayed in the right hand pane
     * of the resource page.
     * @return a new instantiation of the component for each view.
     * Called by: ResourceModel
     */
    public Component getCustomPanel() {
        return new JPanel();
    }

    /**
     * Called when this object is unselected.
     * Called by: ResourceModel
     */
    public void unselect(IPage viewInstance) {
    }

    /**
     * Called when this object is selected.
     * Called by: ResourceModel
     */
    public void select(IPage viewInstance) {
    }

    /**
     * Called when this object needs to execute, (when user double-clicks or menu Open)
     * @return success or failure of run operation
     * Called by: ResourceModel
     */
    public boolean run(IPage viewInstance, IResourceObject selection[]) {
        return false;
    }


    /**
     * Returns the class name of this object.
     * Called by ResourceObject.canRunSelection() method.
     * ResourceObject subclasses can override this method to provide its
     * own implementation.
     */
    public String getClassName() {
        return getClass().getName();
    }


    /**
     * The list of selected objects is delivered in selectionList.  This can be used
     * to detect multiple selection.
     */
    public boolean canRunSelection(IResourceObject selection[]) {
        IResourceObject problemObject = null;
        boolean fReturn = true;

        if (selection.length < 2) {
            return true;
        }

        String firstObjectClassName = null;
        if (selection[0] instanceof ResourceObject) {
            firstObjectClassName =
                    ((ResourceObject) selection[0]).getClassName();
            if (firstObjectClassName == null) {
                firstObjectClassName = selection[0].getClass().getName();
            }
        } else {
            firstObjectClassName = selection[0].getClass().getName();
        }

        String nextObjectClassName = null;

        // this is assuming that if A is accepted by B, B is also accept by A.
        for (int i = 1; i < selection.length; i++) {
            if (selection[i] instanceof ResourceObject) {
                nextObjectClassName =
                        ((ResourceObject) selection[i]).getClassName();
            } else {
                nextObjectClassName = selection[i].getClass().getName();
            }

            if (nextObjectClassName == null ||
                    firstObjectClassName.equals(nextObjectClassName) ==
                    false) {
                problemObject = selection[i];
                break;
            }
        }

        if (problemObject != null) {
            //Debug.println("probjem obj = " +problemObject);
            fReturn = false;
            // TODO: do not display this here, let this be done through IResourceObject
            SuiOptionPane.showMessageDialog(null,
                    problemObject.toString() + " "+
                    resource.getString("multipleselection", "errortext"),
                    resource.getString("multipleselection",
                    "errortitle"), SuiOptionPane.ERROR_MESSAGE);
            ModalDialogUtil.sleep();
        }
        return fReturn;
    }

    /**
     * sends IResourceModelListener.removeMenuItems() notifications to all listeners
     **/
    public void fireRemoveMenuItems(IPage viewInstance,
            IMenuInfo menuInfo) {
        if (viewInstance instanceof ResourcePage) {
            ResourcePage resourcePage = (ResourcePage) viewInstance;
            IResourceModel model = resourcePage.getModel();
            if (model instanceof ResourceModel) {
                ResourceModel taskModel = (ResourceModel) model;
                taskModel.fireRemoveMenuItems(viewInstance, menuInfo);
            }
        }
    }

    /**
     * sends IResourceModelListener.addMenuItems() notifications to all listeners
     **/
    public void fireAddMenuItems(IPage viewInstance, IMenuInfo menuInfo) {
        if (viewInstance instanceof ResourcePage) {
            ResourcePage resourcePage = (ResourcePage) viewInstance;
            IResourceModel model = resourcePage.getModel();
            if (model instanceof ResourceModel) {
                ResourceModel taskModel = (ResourceModel) model;
                taskModel.fireAddMenuItems(viewInstance, menuInfo);
            }
        }
    }

    /**
     * sends IResourceModelListener.disableMenuItem() notifications to all listeners
     **/
    public void fireDisableMenuItem(IPage viewInstance, String menuItemID) {
        if (viewInstance instanceof ResourcePage) {
            ResourcePage resourcePage = (ResourcePage) viewInstance;
            IResourceModel model = resourcePage.getModel();
            if (model instanceof ResourceModel) {
                ResourceModel taskModel = (ResourceModel) model;
                taskModel.fireDisableMenuItem(viewInstance, menuItemID);
            }
        }
    }

    /**
     * sends IResourceModelListener.enableMenuItem() notifications to all listeners
     **/
    public void fireEnableMenuItem(IPage viewInstance, String menuItemID) {
        if (viewInstance instanceof ResourcePage) {
            ResourcePage resourcePage = (ResourcePage) viewInstance;
            IResourceModel model = resourcePage.getModel();
            if (model instanceof ResourceModel) {
                ResourceModel taskModel = (ResourceModel) model;
                taskModel.fireEnableMenuItem(viewInstance, menuItemID);
            }
        }
    }

    /**
     * sends fireChangeStatusItemState() notifications to all listeners
     **/
    public void fireChangeStatusItemState(IPage viewInstance,
            String statusItemID, Object state) {
        if (viewInstance instanceof ResourcePage) {
            ResourcePage taskPage = (ResourcePage) viewInstance;
            IResourceModel model = taskPage.getModel();
            if (model instanceof ResourceModel) {
                ResourceModel taskModel = (ResourceModel) model;
                taskModel.fireChangeStatusItemState(viewInstance,
                        statusItemID, state);
            }
        }
    }
}
