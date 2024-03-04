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

package com.netscape.management.client.ug;

import com.netscape.management.client.console.ConsoleInfo;


/**
 * IResourceDeleteCallBack is used to invoke any server-specific clean up
 * tasks for deleting a resource. The actual implementation for this
 * interface is retrieved from the nsDeleteClassname attribute of the
 * nsAdminResourceEditorExtension object class.
 */
public interface IResourceDeleteCallBack {

    /**
     * The class implementing the IResourceDeleteCallBack must provide the
     * implementation for this method. Any server-specific clean up must
     * be done for deleting the resource.
     *
     * @param ci          the ConsoleInfo with necessary session info
     * @param resourceDN  the distinguished name for the resource to delete
     * @return            true if server-specific clean up is successful;
     *                    false otherwise
     */
    public boolean deleteResource(ConsoleInfo ci, String resourceDN);
}
