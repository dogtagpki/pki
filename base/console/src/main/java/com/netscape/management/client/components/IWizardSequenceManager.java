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
/*
=====================================================================

        WizardSequenceManager.java

        Created by Claude Duguay
        Copyright (c) 1998

=====================================================================
*/


/**
 * A sequence manager determain which page should get displayed
 * next (prev, current, next).
 *
 */
public interface IWizardSequenceManager
{
    /**
     * Get first page's page id
     *
     * @return first page's page id
     *
     */
    public String getFirst();

    /**
     * Set first page
     *
     * @param id id of the first page
     */
    public void setFirst(String id);

    /**
     * Get current page's page id
     *
     * @return currentlypage id
     */
    public String getCurrent();

    /**
     * Set current page
     *
     * @param id id of the current page
     */
    public void setCurrent(String id);

    /**
     * Get next page's page id
     *
     * @param id page id
     * @return next page's page id (relative to id passed in), "" if none exist
     */
    public String getNext(String id);

    /**
     * Set next page's page id
     *
     * @param id page id
     * @param next_id next page's page id (relative to id passed in)
     *
     */
    public void setNext(String id, String next_id);

    /**
     * Get previous page's page id
     *
     * @param id page id
     * @return  previous page's page id (relative to id passed in)
     */

    public String getPrevious(String id);

    /**
     * Set previous page's page id
     *
     * @param id page id
     * @param previous_id previous page id (relative to id passed in)
     */
    public void setPrevious(String id, String previous_id);

    /**
     * Determain if a page is the last page.
     *
     * @param id page id
     * @return true if id match that of last page's page id
     *
     */
    public boolean isLast(String id);

}

