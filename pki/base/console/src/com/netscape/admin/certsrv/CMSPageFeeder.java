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
package com.netscape.admin.certsrv;

import java.util.*;
import javax.swing.*;
import javax.swing.event.*;
import com.netscape.management.client.*;
import com.netscape.management.client.console.*;
import com.netscape.management.client.topology.*;
import com.netscape.management.client.util.*;
import com.netscape.admin.certsrv.config.*;
import netscape.ldap.*;

/**
 *	Netscape Certificate Server 4.0 page model.
 *
 * @author Jack Pan-Chen
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 */
public class CMSPageFeeder extends FrameworkInitializer {
//public class CMSPageFeeder extends PageFeeder {
    /*==========================================================
     * variables
     *==========================================================*/
    public static String RESOURCE_TAB_TYPE = "RESOURCE_TAB_TYPE";
    public static String TASK_TAB_TYPE = "TASK_TAB_TYPE";
    
    private static String PREFIX = "CMSPAGEFEEDER_";

    private ConsoleInfo mConsoleInfo;		// global information
	private CMSServerInfo mServerInfo;		// instance information

	//private TaskPage mTaskPage;		    // task page
	private Hashtable mPages;               // resource pages
	//private ResourcePage mResourcePage;	// resource page
	//private ResourcePage mContentPage;    // content page
    //private ResourcePage mUGPage;         // identity and roles page
    
	private ResourceBundle mResource;       // resource boundle

	/*==========================================================
     * constructors
     *==========================================================*/

	/**
	 *	Constructor.
	 *
	 * @param admin The server instance.
	 * @param info	Global console connection information
	 * @param serverInfo Server instance connection information
	 */
    public CMSPageFeeder( ConsoleInfo info, CMSServerInfo serverInfo ) {
		mConsoleInfo = info;
		mServerInfo = serverInfo;
        mResource = ResourceBundle.getBundle(CMSAdminResources.class.getName());
        mPages = new Hashtable();
        
		setFrameTitle(mResource.getString(PREFIX+"SERVERNAME"));
		setMinimizedImage(CMSAdminUtil.getImage(CMSAdminResources.IMAGE_CERTICON_MEDIUM).getImage());
		setBannerImage(CMSAdminUtil.getThemeImage(CMSAdminResources.IMAGE_BRANDING).getImage());
        setBannerText("");
		//setFrameImage(CMSAdminUtil.getImage(CMSAdminResources.IMAGE_CERTICON_SMALL).getImage());
	}

    /**
     * Retrieve the tab page as needed. If the tab page type not found
     * throws exceptions. If the tab page with the specified name already
     * exist, simply return that page.
     */
    public IPage getPage(String type, String name) throws EAdminException {
        //Debug.println("CMSPageFeeder: getPage() -"+type+"-"+name);
        if (type.trim().equals(TASK_TAB_TYPE)) {
            return null;
/*
            //XXX Support multiple task tab ???
            if (mPages.containsKey("TASK"))
                return (IPage) mPages.get("TASK");
            TaskPage task = createTaskPage();

            // TAKE THIS ONE OUT FOR BETA-1
            mPages.put("TASK", task);
            addPage(task);
            return task;
*/
        }
        
        if (!type.trim().equals(RESOURCE_TAB_TYPE)) {
            throw new EAdminException(mResource.getString(PREFIX+"RESOURCE_TAB_NOT_FOUND"), true);
        }
        
        if (mPages.containsKey(name.trim())) {
            return (IPage) mPages.get(name.trim());    
        } else {
            CMSResourcePage page = new CMSResourcePage(new CMSBaseResourceModel(mConsoleInfo,mServerInfo));
            String title;
            try {
                title = mResource.getString(PREFIX+name.trim());
            } catch (MissingResourceException e) {
                title = "Missing Title";
            }
            page.setPageTitle(title);
            mPages.put(name.trim(), page);
            addPage(page);
            return page;
        }
    }


    /**
     * Expend resource trees insde each individual pages
     */
    public void expendPages() {
        for (Enumeration e = mPages.keys() ; e.hasMoreElements() ;) {
              String name = (String)e.nextElement();
              IPage page = (IPage)mPages.get(name);
              if (page instanceof CMSResourcePage)
                  ((CMSResourcePage)page).getTree().expandRow(0);
          }
    }
    
    
    /*==========================================================
	 * private methods
     *==========================================================*/

	/**
	 * Create the directory server task tab page by finding all task
	 * entries in the directory for this instance.
	 */
	private TaskPage createTaskPage() {
		TaskModel model = new CMSTaskModel(mConsoleInfo, mServerInfo);
		return new TaskPage( model );
	}
}
