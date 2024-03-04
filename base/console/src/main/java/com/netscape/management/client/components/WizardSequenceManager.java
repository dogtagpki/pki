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
import java.util.*;


/**
 * Default sequence manager
 *
 */
public class WizardSequenceManager
     implements IWizardSequenceManager
{

    protected String first;
    protected String current;
    protected Hashtable next;
    protected Hashtable prev;

    /**
     * Create a default wizard sequence manager
     *
     *
     */
    public WizardSequenceManager()
    {
        next = new Hashtable();
        prev = new Hashtable();
    }

    /**
     * Get first page's page id
     *
     * @return first page's page id
     *
     */
    public String getFirst()
    {
        return first;
    }

    /**
     * Set first page
     *
     * @param id id of the first page
     */
    public void setFirst(String first)
    {
        //System.out.println("First: " + first);
        this.first = first;
    }

    /**
     * Determain if a page is the last page.
     *
     * @param id page id
     * @return true if id match that of last page's page id
     *
     */
    public boolean isLast(String id) {
        //System.out.println("isLast: " + id);
        return getNext(id).equals("");
    }


    /**
     * Get current page's page id
     *
     * @return currentlypage id
     */
    public String getCurrent()
    {
        return current;
    }

    /**
     * Set current page
     *
     * @param id id of the current page
     */
    public void setCurrent(String current)
    {
        //System.out.println("Current: " + current);
        this.current = current;
    }

    /**
     * Set next page's page id
     *
     * @param id page id
     * @param next_id next page's page id (relative to id passed in)
     *
     */
    public String getNext(String name)
    {
        //System.out.println("Get next " + name);
        if (!next.containsKey(name)) return "";
        return (String)next.get(name);
    }

    /**
     * Set next page's page id
     *
     * @param id page id
     * @param next_id next page's page id (relative to id passed in)
     *
     */
    public void setNext(String name, String link)
    {
        //System.out.println("Link: " + name + " --> " + link);
        if (next.containsKey(name)) next.remove(name);
        if (prev.containsKey(link)) prev.remove(link);
        next.put(name, link);
        prev.put(link, name);
    }

    /**
     * Get previous page's page id
     *
     * @param id page id
     * @return  previous page's page id (relative to id passed in)
     */
    public String getPrevious(String name)
    {
        //System.out.println("Get previous " + name);
        if (!prev.containsKey(name)) return "";
        return (String)prev.get(name);
    }

    /**
     * Set previous page's page id
     *
     * @param id page id
     * @param previous_id previous page id (relative to id passed in)
     */
    public void setPrevious(String name, String link)
    {
        //System.out.println("Link: " + link + " --> " + name);
        if (prev.containsKey(name)) prev.remove(name);
        if (next.containsKey(link)) next.remove(link);
        prev.put(name, link);
        next.put(link, name);
    }
}
