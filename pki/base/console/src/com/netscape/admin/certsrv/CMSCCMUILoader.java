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

import com.netscape.management.client.*;
import com.netscape.management.client.util.*;
import com.netscape.admin.certsrv.config.*;
import com.netscape.admin.certsrv.ug.*;


/**
 * Netscape Certificate Server 4.0 CCM UI Loader.
 *
 * This class is responsible for the loading of UI components associated with
 * the ccm functionality.
 *
 * @author Jack Pan-Chen
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 * @date	 	03/30/97
 */
public class CMSCCMUILoader implements ISubSystemUILoader {

    /*==========================================================
     * variables
     *==========================================================*/
    private CMSUIFramework mUIFramework;      //parent framework

	/*==========================================================
     * constructors
     *==========================================================*/
    public CMSCCMUILoader(CMSUIFramework framework) {
        mUIFramework = framework;
    }

    /*==========================================================
	 * public methods
     *==========================================================*/
    public void register() {
       //register subsystem UI
        try {
            
            //task tab
            IPage task = mUIFramework.getPage(CMSPageFeeder.TASK_TAB_TYPE,"");
            
            //config tab
            CMSResourcePage page = (CMSResourcePage) mUIFramework.getPage(CMSPageFeeder.RESOURCE_TAB_TYPE,"CONFIGURATION");
            CMSBaseResourceModel model = (CMSBaseResourceModel) page.getModel();
            populateConfigContent(model);
            
            /*acl tab
            page = (CMSResourcePage) mUIFramework.getPage(CMSPageFeeder.RESOURCE_TAB_TYPE,"ACCESSCONTROLLIST");
            model = (CMSBaseResourceModel) page.getModel();
            populateACLContent(model);
            */
            
        }catch(Exception e) {
            Debug.println("CMSCCMUILoader: register() config - "+e.toString());
        }

    }

    /*==========================================================
	 * protected methods
     *==========================================================*/
    protected void populateConfigContent(CMSBaseResourceModel model) {
        CMSResourceObject node;
        CMSTabPanel tabPane;
        
        //ccm node
        node = new CMSResourceObject("CCMCONFIG");
        tabPane = new CMSTabPanel(model, node);
        tabPane.addTab(new CMSBlankPanel(model,tabPane,"Service Ports"));
        tabPane.addTab(new CMSBlankPanel(model,tabPane,"Password Distribution"));
        node.setCustomPanel(tabPane);
        node.setIcon( CMSAdminUtil.getImage(CMSAdminResources.IMAGE_FOLDER));
        node.setAllowsChildren(true);
        
        model.addSubSystemNode(node);
    }

    /*
    protected void populateACLContent(CMSBaseResourceModel model) {
        CMSResourceObject list, node;
        list = model.getByNickName("ACL");
        node = new CMSResourceObject("CCMACL");
        node.setCustomPanel(new CMSBlankPanel(model));
        node.setIcon( CMSAdminUtil.getImage(CMSAdminResources.IMAGE_DOCUMENT));
        node.setAllowsChildren(false);
        list.add(node);        
    }
    */
}
