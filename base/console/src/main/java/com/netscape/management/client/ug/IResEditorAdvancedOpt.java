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

import com.netscape.management.client.console.*;


/**
 * IResEditorAdvancedOpt is used for supporting the advanced option in the
 * resource editor. This is useful when more functionality than the resource
 * editor page framework is needed. In order to use the advanced option,
 * the handler for the advanced option should implement this interface and
 * be registered to the ResourceEditor.
 *
 * @see ResourceEditor#registerAdvancedOption(IResEditorAdvancedOpt)
 */
public interface IResEditorAdvancedOpt {
    /**
     * Returns the text label for the advanced option.
     *
     * @return the text label for the advanced option
     */
    public String getButtonText();


    /**
    * Invokes the handler routine for the advanced option.
    *
    * @param info        session information
    * @param observable  the observable object
    * @return            true if successful; false otherwise
    */
    public boolean run(ConsoleInfo info, ResourcePageObservable observable);
}
