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
import javax.swing.tree.*;

/**
 * Defines data model for ResourcePage; responsible for providing:
 * - data for tree nodes (using methods inherited from TreeModel)
 * - right hand panel for each tree node
 * - sending events (via IResourceModelListener)
 * - receiving events (via action methods)
 *
 * @see IResourceModelListener
 * @see ResourceModel
 */
public interface IResourceModel extends TreeModel {
    /**
      * Registers a listener that is interested in receiving events.
      * Typically will be called by ResourcePage.
      *
      * @param l		IResourceModelListener to be added to listener list
      */
    public abstract void addIResourceModelListener(
            IResourceModelListener l);

    /**
     * Deregisters a listener previously added by the addIResourceModelListener method.
     *
     * @param l		IResourceModelListener to be removed from listener list
     */
    public abstract void removeIResourceModelListener(
            IResourceModelListener l);

    /**
     * Returns object that renders contents (appears in right hand panel)
     * for currently selected node in tree (left hand side).
     *
     * @param viewInstance		IPage instance which calls this method
     * @param node				IResourceObject which is selected in tree
     */
    public abstract Component getCustomPanel(IPage viewInstance,
            IResourceObject node);

    /**
     * Notification that one or more nodes have been selected in tree.
     *
     * @param viewInstance		IPage instance which calls this method
     * @param selection			array of IResourceObjects currently selected in tree
     * @param previousSelection	array of IResourceObjects previously selected in tree
     */
    public abstract void actionObjectSelected(IPage viewInstance,
            IResourceObject[] selection,
            IResourceObject[] previousSelection);

    /**
     * Notification that 'run' action should be performed on the selected tree node(s).
     * Called when user double clicks on a tree node.  For example, called when
     * user drills down to server instance, then double-clicks on it to launch
     * Server window.
     *
     * @param viewInstance		IPage instance which calls this method
     * @param selection			array of IResourceObjects currently selected in tree
     */
    public abstract void actionObjectRun(IPage viewInstance,
            IResourceObject[] selection);

    /**
     * Notification from Console that window is closing.
     * (in response to a Close or Exit selection).
     * In response, a CloseVetoException may be thrown which
     * causes Console to inform user that there is unsaved
     * data in this tab, and allows user to abort close operation.
     *
     * @param parent				IFramework parent of this object
     * @exception CloseVetoException thrown to veto the close action.
     */
    public abstract void actionViewClosing(IPage viewInstance)
            throws CloseVetoException;
}
