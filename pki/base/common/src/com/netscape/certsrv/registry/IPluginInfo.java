// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.registry;


import java.util.Locale;


/**
 * The plugin information includes name, 
 * class name, and description. The localizable
 * name and description are information
 * for end-users.
 * <p>
 *
 * The class name can be used to create
 * an instance of the plugin.
 * <p>
 *
 * @version $Revision$, $Date$
 */
public interface IPluginInfo {

    /**
     * Retrieves the localized plugin name.
     *
     * @param locale end-user locale
     * @return plugin name
     */
    public String getName(Locale locale);

    /**
     * Retrieves the localized plugin description.
     *
     * @param locale end-user locale
     * @return plugin description
     */
    public String getDescription(Locale locale);

    /**
     * Retrieves the class name of the plugin.
     * Instance of plugin can be created with
     * <p>
     * Class.forName(info.getClassName());
     *
     * @return java class name
     */
    public String getClassName();
}
