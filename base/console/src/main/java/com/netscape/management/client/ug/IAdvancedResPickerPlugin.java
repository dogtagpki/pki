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

import java.util.Vector;

/**
 * Interface to change the advanced resource picker plugin.
 *
 * @author  <a href=mailto:terencek@netscape.com>Terence Kwan</a>
 * @version 0.2 9/3/97
 */

public interface IAdvancedResPickerPlugin extends IResourcePickerPlugin {

    // process control

    /**
     * start the search action
     */
    public abstract void start();

    /**
     * stop the search action
     */
    public abstract void stop();

    /**
     * return the current search status.
     *
     * @return true if the search is finished. false otherwise
     */
    public abstract boolean isFinish();

    // display control
    /**
     * get back the list of results afte rthe search
     *
     * @return list of DN strings resulted from the search.
     */
    public abstract String[] getResultHeader();

    /**
     * get the result count
     *
     * @return the number of DN returned from the search
     */
    public abstract int getResultCount();

    /**
     * return the search result of given index
     *
     * @return search result of given index
     */
    public abstract Vector getResult(int index); // the vector will be either image or string

    /**
     * return the search result of given index
     *
     * @return search result of given index
     */
    public abstract String getResultValue(int index);
}
