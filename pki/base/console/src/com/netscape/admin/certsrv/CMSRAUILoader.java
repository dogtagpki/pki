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
 * Netscape Certificate Server 4.0 Kernel UI Loader.
 *
 * This class is responsible for the loading of UI components associated with
 * the kernel functionality.
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @date	 	03/30/97
 */
public class CMSRAUILoader implements ISubSystemUILoader {

    /*==========================================================
     * variables
     *==========================================================*/
    private CMSUIFramework mUIFramework;      //parent framework

	/*==========================================================
     * constructors
     *==========================================================*/
    public CMSRAUILoader(CMSUIFramework framework) {
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
            Debug.println("CMSRAUILoader: register() config - "+e.toString());
        }

    }

    /*==========================================================
	 * protected methods
     *==========================================================*/
    protected void populateConfigContent(CMSBaseResourceModel model) {
        CMSResourceObject list, node;
        CMSTabPanel tabPane;

        CMSResourceObject authnode = new CMSResourceObject("AUTH");
        CMSUGTabPanel tabPane1 = new CMSUGTabPanel(model, authnode);
        tabPane1.addTab(new AuthInstanceTab(model));
        tabPane1.addTab(new AuthImplTab(model));
        authnode.setCustomPanel(tabPane1);
        authnode.setIcon( CMSAdminUtil.getImage(
          CMSAdminResources.IMAGE_AUTHOBJECT));
        authnode.setAllowsChildren(false);
        model.addSubSystemNode(authnode);

        // jobs scheduler node
        CMSResourceObject jobsnode = new CMSResourceObject("JOBSCHED");
        tabPane = new CMSTabPanel(model, jobsnode);
        tabPane.addTab(new JobsSettingPanel("JOBSGENERAL", tabPane));

        jobsnode.setCustomPanel(tabPane);
        jobsnode.setIcon( CMSAdminUtil.getImage(
                        CMSAdminResources.IMAGE_JOBSOBJECT));

        jobsnode.setAllowsChildren(true);
        CMSResourceObject cnode = new CMSResourceObject("JOBS");

        tabPane1 = new CMSUGTabPanel(model, cnode);
        tabPane1.addTab(new JobsInstanceTab(model));
        tabPane1.addTab(new JobsImplTab(model));
        cnode.setCustomPanel(tabPane1);
        cnode.setIcon( CMSAdminUtil.getImage(
                        CMSAdminResources.IMAGE_JOBSOBJECT));
                jobsnode.add(cnode);
        cnode.setAllowsChildren(false);
        model.addSubSystemNode(jobsnode);

        //ra node
        list = new CMSResourceObject("RACONFIG");
        tabPane = new CMSTabPanel(model, list);
//        tabPane.addTab(new CMSRAGeneralPanel(tabPane));
        tabPane.addTab(new CMSRAConnectorPanel(model,tabPane));
        list.setIcon( CMSAdminUtil.getImage(CMSAdminResources.IMAGE_FOLDER));
        list.setAllowsChildren(true);
        list.setCustomPanel(tabPane);
        
        //policies sub node
        CMSResourceObject node2;
        node = new CMSResourceObject("POLICIES");
        CMSUGTabPanel tabPane2 = new CMSUGTabPanel(model, node);
        tabPane2.addTab(new PolicyInstanceTab(model, DestDef.DEST_RA_POLICY_ADMIN));
        tabPane2.addTab(new PolicyImplTab(model, DestDef.DEST_RA_POLICY_ADMIN));
        node.setCustomPanel(tabPane2);
        node.setIcon( CMSAdminUtil.getImage(CMSAdminResources.IMAGE_RULEOBJECT));
        node.setAllowsChildren(false);
        list.add(node);

        // profiles
        node = new CMSResourceObject("PROFILES");
        CMSUGTabPanel tabPane3 = new CMSUGTabPanel(model, node);
        tabPane3.addTab(new ProfileInstanceTab(model, DestDef.DEST_RA_PROFILE_ADMIN));
        tabPane3.addTab(new ProfileImplTab(model, DestDef.DEST_REGISTRY_ADMIN));
        node.setCustomPanel(tabPane3);
        node.setIcon( CMSAdminUtil.getImage(CMSAdminResources.IMAGE_RULEOBJECT))
;
        node.setAllowsChildren(false);
        list.add(node);

		// notification
        CMSResourceObject notificationNode = new CMSResourceObject("NOTIFICATION");
        tabPane = new CMSTabPanel(model, notificationNode);
		tabPane.addTab(new RequestCompletePanel("NOTIFYREQCOMPLETE",
												tabPane,
												DestDef.DEST_RA_ADMIN));
		tabPane.addTab(new RequestInQPanel("NOTIFYREQINQ", tabPane,
										   DestDef.DEST_RA_ADMIN));

        notificationNode.setCustomPanel(tabPane);
        notificationNode.setIcon( CMSAdminUtil.getImage(
			CMSAdminResources.IMAGE_JOBSOBJECT));

		notificationNode.setAllowsChildren(false);
		list.add(notificationNode);

        
        /* servlet sub node - XXX NOT FOR B1
        CMSResourceObject node3;
        node3 = new CMSResourceObject("SERVLET");
        CMSUGTabPanel tabPane3 = new CMSUGTabPanel(model, node3);
        tabPane3.addTab(new ServletInstanceTab(model, 
          DestDef.DEST_RA_SERVLET_ADMIN));
        tabPane3.addTab(new ServletImplTab(model, 
          DestDef.DEST_RA_SERVLET_ADMIN));
        node3.setCustomPanel(tabPane3);
        node3.setIcon(CMSAdminUtil.getImage(CMSAdminResources.IMAGE_SERVLETOBJECT));
        node3.setAllowsChildren(false);
        list.add(node3);
        */

        /*extensions sub node
        node = new CMSResourceObject("EXTENSIONS");
        tabPane = new CMSTabPanel(model, node);
        tabPane.addTab(new CMSBlankPanel(model,tabPane,"Configuration"));
        tabPane.addTab(new CMSBlankPanel(model,tabPane,"Registartion"));
        node.setCustomPanel(tabPane);
        node.setIcon( CMSAdminUtil.getImage(CMSAdminResources.IMAGE_PLUGIN));
        node.setAllowsChildren(false);
        list.add(node);
        */
        
        /*backup restore sub node
        node = new CMSResourceObject("BACKUP");
        tabPane = new CMSTabPanel(model, node);
        tabPane.addTab(new CMSBlankPanel(model,tabPane,"Backup"));
        tabPane.addTab(new CMSBlankPanel(model,tabPane,"Restore"));
        node.setCustomPanel(tabPane);
        node.setIcon( CMSAdminUtil.getImage(CMSAdminResources.IMAGE_GENERICOBJ));
        node.setAllowsChildren(false);
        list.add(node);
        */
        
        //ldap publishing
        //node = new CMSResourceObject("PUBLISHING");
        //tabPane = new CMSTabPanel(model, node);
        //tabPane.addTab(new CMSRALDAPPanel(tabPane));
        //tabPane.addTab(new CMSUserCertSettingPanel("RAUSERCERTSETTING",tabPane));
        //node.setCustomPanel(tabPane);
        //node.setIcon( CMSAdminUtil.getImage(CMSAdminResources.IMAGE_LDAPPUB));
        //node.setAllowsChildren(false);
        //list.add(node);

        /*webgateway
        node = new CMSResourceObject("GATEWAY");
        tabPane = new CMSTabPanel(model, node);
        tabPane.addTab(new CMSBlankPanel(model,tabPane,"VGI Setting"));
        tabPane.addTab(new CMSBlankPanel(model,tabPane,"Error Responses"));
        node.setCustomPanel(tabPane);
        node.setIcon( CMSAdminUtil.getImage(CMSAdminResources.IMAGE_FOLDER));
        node.setAllowsChildren(false);
        list.add(node);
        */
        
        model.addSubSystemNode(list);
    }
    
    /*
    protected void populateRepositoryContent(CMSBaseResourceModel model) {
        CMSResourceObject list, node;
        
        //ra repositories node
        list = new CMSResourceObject("RAREPOSITORIES");
        list.setCustomPanel(new CMSBlankPanel(model));
        list.setIcon( CMSAdminUtil.getImage(CMSAdminResources.IMAGE_DBCONATINER));
        list.setAllowsChildren(true);
        node = new CMSResourceObject("RAREQUESTS");
        node.setCustomPanel(new CMSBlankPanel(model));
        node.setIcon( CMSAdminUtil.getImage(CMSAdminResources.IMAGE_DBOBJECT));
        node.setAllowsChildren(false);
        list.add(node);
        node = new CMSResourceObject("RACERTIFICATE");
        node.setCustomPanel(new CMSBlankPanel(model));
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
        node = new CMSResourceObject("RAACL");
        node.setCustomPanel(new CMSBlankPanel(model));
        node.setIcon( CMSAdminUtil.getImage(CMSAdminResources.IMAGE_DOCUMENT));
        node.setAllowsChildren(false);
        list.add(node);        
    }
    */

}
