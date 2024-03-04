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

import java.util.*;
import com.netscape.management.client.console.*;
import com.netscape.management.client.*;

/**
 * Defines properties and functionality for a type of plugin that
 * extends the Default View of the topology tree.
 */
public interface ITopologyPlugin {
    /**
      * initialize the plugin object
      */
    public void initialize(ConsoleInfo info);

    /**
     * return a list of top level object which implements IResourceObject
     * and MutableTreeNode interface.
     */
    public Vector getTopNodes();

    /**
     * return a list of products that lie under the specified tree node.
     * The return vector is a list of object which implements
     * IResourceObject and MutableTreeNode interface.
     */
    public Vector getAdditionalChildren(ResourceObject t);

    /**
     * inside the topology, each node will have a unique ID. This routine is used to get the
     * unique id by given the node object.
     *
     * @param res resource node object
     * @return ID of the given node object
     */
    public String getIDByResourceObject(ResourceObject res);

    /**
     * get the node object by using the node ID.
     *
     * @param id ID of the resource object
     * @return resource object
     */
    public ResourceObject getResourceObjectByID(String id);
}
