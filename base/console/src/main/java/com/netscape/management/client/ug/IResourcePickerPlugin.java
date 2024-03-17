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

import java.awt.Component;
import com.netscape.management.client.console.ConsoleInfo;


/**
 * IResourcePickerPlugin is the interface that must be implemented by the
 * search plugins to the ResourcePickerDlg.
 */
public interface IResourcePickerPlugin {

    /**
     * Initializes the plugin with the session information.
     *
     * @param info  session information
     */
    public void initialize(ConsoleInfo info);


    /**
     * Retrieves the unique string ID for the plugin.
     *
     * @return  unique ID for the plugin
     */
    public String getID();


    /**
     * Retrieves the plugin name to display in the toggle button.
     *
     * @return  the plugin name to display
     */
    public String getDisplayName();


    /**
     * Retrieves the UI component to display when the plugin is selected.
     *
     * @return  the UI component to display
     */
    public Component getSearchUI();


    /**
     * Displays the plugin specific help.
     */
    public void help();


    /**
     * Retrieves the string to search for.
     *
     * @return  the search string
     */
    public String getFilterString();
}
