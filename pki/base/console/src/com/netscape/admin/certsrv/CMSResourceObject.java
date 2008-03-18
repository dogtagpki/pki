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
import java.awt.*;
import javax.swing.*;
import javax.swing.tree.*;
import com.netscape.management.client.util.*;
import com.netscape.management.client.*;

/**
 *	Netscape Certificate Server 4.0 Node Object.<br>
 *
 * @author Jack Pan-Chen
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 * @see com.netscape.admin.certsrv
 */
public class CMSResourceObject extends ResourceObject {

    /*==========================================================
     * variables
     *==========================================================*/
    private final String PREFIX = "CMSRESOURCEOBJECT_";
    private JPanel mRightPane;
    private String mNickName;
    protected ResourceBundle mResource = ResourceBundle.getBundle(CMSAdminResources.class.getName());
    
	/*==========================================================
	 * constructors
	 *==========================================================*/

	/**
	 *	Creates empty resource object.
	 */
	public CMSResourceObject() {
	    super();
	    mNickName = "";
	}

	/**
	 *	Creates resource object with specified keyword/nickname.
	 */
    public CMSResourceObject(String keyword) {
        this();
        mNickName = keyword;
        String sDisplayName;
        try {
            sDisplayName = mResource.getString(PREFIX+keyword+"_TITLE");
        } catch(MissingResourceException e) {
            sDisplayName = keyword;
        }
        setName(sDisplayName);
    }

	/**
	 *	Creates resource object with specified keyword/nickname and icons.
	 */
	public CMSResourceObject(String keyword, Icon icon, Icon largeIcon) {
	    this();
	    mNickName = keyword;
	    String sDisplayName;
        try {
            sDisplayName = mResource.getString(PREFIX+keyword+"_TITLE");
        } catch(MissingResourceException e) {
            sDisplayName = "MissingTitle";
        }
	    setName(sDisplayName);
	    setIcon(icon);
	    setLargeIcon(largeIcon);
	}

    /**
     * Returns the internal nickname for this resource object
     */
    public String getNickName() {
        return mNickName;    
    }
    
	/**
	 * Returns the AWT Component that is displayed in the right hand pane
	 * of the resource page.
	 * @return a new instantiation of the component for each view.
     * Called by: ResourceModel
	 */
	public Component getCustomPanel()
	{
		return mRightPane;
	}

	/**
	 * Set the right hand panel to be shown
	 * @param panel right hand panel
	 */
	public void setCustomPanel(JPanel panel) {
	    mRightPane = panel;
	}
	
	protected MenuItemText getMenuItemText(String keyword) {
		ResourceBundle mResource = ResourceBundle.getBundle(
			CMSAdminResources.class.getName());
		String name = mResource.getString("GENERAL_MENU_"+keyword+"_LABEL");
		if (name == null)
			name = "Missing Label";
		String desc = mResource.getString("GENERAL_MENU_"+keyword+"_DESC");
		if (desc == null)
			desc = " ";
		return new MenuItemText( keyword, name, desc);
	}	

}
