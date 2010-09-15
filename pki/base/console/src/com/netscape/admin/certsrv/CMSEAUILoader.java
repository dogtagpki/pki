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
import com.netscape.certsrv.common.*;
import com.netscape.admin.certsrv.notification.*;

/**
 * Netscape Certificate Server 4.0 Escrow Authority UI Loader.
 *
 * This class is responsible for the loading of UI components associated with
 * the ea functionality.
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @date	 	03/30/97
 */
public class CMSEAUILoader implements ISubSystemUILoader {

    /*==========================================================
     * variables
     *==========================================================*/
    private CMSUIFramework mUIFramework;      //parent framework

	/*==========================================================
     * constructors
     *==========================================================*/
    public CMSEAUILoader(CMSUIFramework framework) {
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
            
            /*repos tab
            page = (CMSResourcePage) mUIFramework.getPage(CMSPageFeeder.RESOURCE_TAB_TYPE,"CONTENT");
            model = (CMSBaseResourceModel) page.getModel();
            populateRepositoryContent(model);
            */
            
            /*acl tab
            page = (CMSResourcePage) mUIFramework.getPage(CMSPageFeeder.RESOURCE_TAB_TYPE,"ACCESSCONTROLLIST");
            model = (CMSBaseResourceModel) page.getModel();
            populateACLContent(model);
            */
            
        }catch(Exception e) {
            Debug.println("CMSEAUILoader: register() config - "+e.toString());
        }

    }

    /*==========================================================
	 * protected methods
     *==========================================================*/
    protected void populateConfigContent(CMSBaseResourceModel model) {
        CMSResourceObject list, node;
        CMSTabPanel tabPane;

        //ca node
        list = new CMSResourceObject("EACONFIG");
        tabPane = new CMSTabPanel(model, list);
        tabPane.addTab(new CMSEAGeneralPanel(tabPane));
        list.setIcon( CMSAdminUtil.getImage(CMSAdminResources.IMAGE_FOLDER));
        list.setAllowsChildren(false);
        list.setCustomPanel(tabPane);

        model.addSubSystemNode(list);
    }
    
    /*
    protected void populateRepositoryContent(CMSBaseResourceModel model) {
        CMSResourceObject list, node;
        
        //ca repositories node
        list = new CMSResourceObject("EAREPOSITORIES");
        list.setCustomPanel(new CMSBlankPanel(model));
        list.setIcon( CMSAdminUtil.getImage(CMSAdminResources.IMAGE_DBCONATINER));
        list.setAllowsChildren(true);
        node = new CMSResourceObject("EAREQUESTS");
        node.setCustomPanel(new KeyRequestPanel(model, node));
        node.setIcon( CMSAdminUtil.getImage(CMSAdminResources.IMAGE_DBOBJECT));
        node.setAllowsChildren(false);
        list.add(node);
        node = new CMSResourceObject("EAKEY");
        node.setCustomPanel(new KeyRepositoryPanel(model, node));
        node.setIcon( CMSAdminUtil.getImage(CMSAdminResources.IMAGE_DBOBJECT));
        node.setAllowsChildren(false);
        list.add(node);
        model.addSubSystemNode(list);
    }
    */
    /*
    protected void populateACLContent(CMSBaseResourceModel model) {
        CMSResourceObject list, node;
        list = model.getByNickName("ACL");
        node = new CMSResourceObject("EAACL");
        node.setCustomPanel(new CMSBlankPanel(model));
        node.setIcon( CMSAdminUtil.getImage(CMSAdminResources.IMAGE_DOCUMENT));
        node.setAllowsChildren(false);
        list.add(node);        
    }
    */

}
