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

/**
 * DirNodeEvent
 * 
 * Represents action events in the tree.
 *
 * @version 1.0
 * @author rweltman
 **/
package com.netscape.management.client.components;
public class DirNodeEvent {

	/**
	 * Constructor
	 *
	 * @param nodes Array of selected tree nodes
	 * @param id Type of action
	 * @param param Additional String information
	 */
    public DirNodeEvent( IDirNode[] nodes, int id, String param ) {
		_nodes = nodes;
		_id = id;
		_param = param;
	}

	/**
	 * Get the nodes selected at the time of the action
	 *
	 * @return The nodes selected at the time of the action
	 */
	public IDirNode[] getNodes() {
		return _nodes;
	}

	/**
	 * Get the ID of the action
	 *
	 * @return The ID of the action
	 */
	public int getID() {
		return _id;
	}

	/**
	 * Get additional info associated with the action
	 *
	 * @return Possibly null info associated with the action
	 */
	public String getParamString() {
		return _param;
	}

	public static final int RUN = 0;

	private IDirNode[] _nodes;
	private int _id;
	private String _param;
}


