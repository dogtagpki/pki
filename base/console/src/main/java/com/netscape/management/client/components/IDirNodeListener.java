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
import java.util.EventListener;

/**
 * IDirNodeListener
 * 
 * For clients wanting to be notified of selection or action events
 * in the tree.
 *
 * @version 1.0
 * @author rweltman
 **/
public interface IDirNodeListener extends EventListener {
	/**
	 * The selection changed.
	 *
	 * @param nodes Array of selected tree nodes
	 */
    public void selectionChanged( IDirNode[] nodes );

	/**
	 * An action was invoked using the mouse or keyboard.
	 *
	 * @param ev Object indicating the type of event.
	 */
    public void actionInvoked( DirNodeEvent ev );
}
