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
import com.netscape.admin.certsrv.menu.*;
import com.netscape.certsrv.common.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.notification.*;
import java.util.*;

/**
 * Netscape Certificate Server 4.0 Certificate Authority UI Loader.
 *
 * This class is responsible for the loading of UI components associated with
 * the ca functionality.
 *
 * @author Jack Pan-Chen
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 * @date        03/30/97
 */
public class CMSCAUILoader implements ISubSystemUILoader {

    /*==========================================================
     * variables
     *==========================================================*/
    private CMSUIFramework mUIFramework;      //parent framework

    /*==========================================================
     * constructors
     *==========================================================*/
    public CMSCAUILoader(CMSUIFramework framework) {
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
            model.setResourcePage(page);
            populateConfigContent(model);
            
            /*repos tab
            page = (CMSResourcePage) mUIFramework.getPage(CMSPageFeeder.RESOURCE_TAB_TYPE,"CONTENT");
            model = (CMSBaseResourceModel) page.getModel();
            populateRepositoryContent(model);
            populateRepositoryMenu(page);
            */
            
            /*acl tab
            page = (CMSResourcePage) mUIFramework.getPage(CMSPageFeeder.RESOURCE_TAB_TYPE,"ACCESSCONTROLLIST");
            model = (CMSBaseResourceModel) page.getModel();
            populateACLContent(model);
            */
            
        }catch(Exception e) {
            Debug.println("CMSCAUILoader: register() config - "+e.toString());
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

        //ca node
        list = new CMSResourceObject("CACONFIG");
        tabPane = new CMSTabPanel(model, list);
        tabPane.addTab(new CMSCAGeneralPanel(tabPane));
        //tabPane.addTab(new CMSCRLSettingPanel(tabPane));
        tabPane.addTab(new CMSCAConnectorPanel(model,tabPane));
        //tabPane.addTab(new CMSCACLMPanel(tabPane));
        list.setIcon( CMSAdminUtil.getImage(CMSAdminResources.IMAGE_FOLDER));
        list.setAllowsChildren(true);
        list.setCustomPanel(tabPane);
        
        //policies sub node
        //CMSResourceObject node2;
        node = new CMSResourceObject("POLICIES");
        CMSUGTabPanel tabPane2 = new CMSUGTabPanel(model, node);
        tabPane2.addTab(new PolicyInstanceTab(model, DestDef.DEST_CA_POLICY_ADMIN));
        tabPane2.addTab(new PolicyImplTab(model, DestDef.DEST_CA_POLICY_ADMIN));
        node.setCustomPanel(tabPane2);
        node.setIcon( CMSAdminUtil.getImage(CMSAdminResources.IMAGE_RULEOBJECT));
        node.setAllowsChildren(false);
        //list.add(node);

        // profiles
        node = new CMSResourceObject("PROFILES");
        CMSUGTabPanel tabPane3 = new CMSUGTabPanel(model, node);
        tabPane3.addTab(new ProfileInstanceTab(model, DestDef.DEST_CA_PROFILE_ADMIN));
        tabPane3.addTab(new ProfileImplTab(model, DestDef.DEST_REGISTRY_ADMIN));
        node.setCustomPanel(tabPane3);
        node.setIcon( CMSAdminUtil.getImage(CMSAdminResources.IMAGE_RULEOBJECT));
        node.setAllowsChildren(false);
        list.add(node);


		// notification
        CMSResourceObject notificationNode = new CMSResourceObject("NOTIFICATION");
        tabPane = new CMSTabPanel(model, notificationNode);
		tabPane.addTab(new RequestCompletePanel("NOTIFYREQCOMPLETE",
												tabPane,
												DestDef.DEST_CA_ADMIN));
		tabPane.addTab(new RequestRevokedPanel("NOTIFYREVCOMPLETE",
												tabPane,
												DestDef.DEST_CA_ADMIN));
        tabPane.addTab(new RequestInQPanel("NOTIFYREQINQ", tabPane,
										   DestDef.DEST_CA_ADMIN));

        notificationNode.setCustomPanel(tabPane);
        notificationNode.setIcon( CMSAdminUtil.getImage(
			CMSAdminResources.IMAGE_JOBSOBJECT));

		notificationNode.setAllowsChildren(false);
		list.add(notificationNode);

        
        /* servlet sub node - XXX NOT FOR B1
           Servlet Instance Tab code is under config/servlet. It has
		   been 'cvs removed'. It needs porting to new UI.
        CMSResourceObject node3;
        node3 = new CMSResourceObject("SERVLET");
        CMSUGTabPanel tabPane3 = new CMSUGTabPanel(model, node3);
        tabPane3.addTab(new ServletInstanceTab(model,
          DestDef.DEST_CA_SERVLET_ADMIN));
        tabPane3.addTab(new ServletImplTab(model,
          DestDef.DEST_CA_SERVLET_ADMIN));
        node3.setCustomPanel(tabPane3);
        node3.setIcon(CMSAdminUtil.getImage(CMSAdminResources.IMAGE_SERVLETOBJECT));
        node3.setAllowsChildren(false);
        list.add(node3);
        */

        /*extensions sub node
        node = new CMSResourceObject("EXTENSIONS");
        tabPane = new CMSTabPanel(model, node);
        tabPane.addTab(new CMSBlankPanel(model,tabPane,"Configuration"));
        tabPane.addTab(new CMSBlankPanel(model,tabPane,"Registration"));
        node.setCustomPanel(tabPane);
        node.setIcon( CMSAdminUtil.getImage(CMSAdminResources.IMAGE_PLUGIN));
        node.setAllowsChildren(false);
        list.add(node);
        */
        
        /* crl extensions sub node
        node = new CMSResourceObject("CRLEXTENSIONS");
        CMSUGTabPanel crlExtTabPane = new CMSUGTabPanel(model, node);
        crlExtTabPane.addTab(new CRLExtensionsInstanceTab(model, DestDef.DEST_CA_ADMIN));
        node.setCustomPanel(crlExtTabPane);
        node.setIcon( CMSAdminUtil.getImage(CMSAdminResources.IMAGE_RULEOBJECT));
        node.setAllowsChildren(false);
        list.add(node);
        */

        // crl issuing points
        node = new CMSResourceObject("CRLIPS");
        CMSTabPanel crlIPsTabPane = new CMSTabPanel(model, node);
        crlIPsTabPane.addTab(new CMSCRLIPPanel(model, crlIPsTabPane));
        node.setCustomPanel(crlIPsTabPane);
        node.setIcon( CMSAdminUtil.getImage(CMSAdminResources.IMAGE_RULEOBJECT));
        node.setAllowsChildren(true);
        list.add(node);

        CMSResourceObject crlsNode = node;
        AdminConnection ac = model.getServerInfo().getAdmin();
        NameValuePairs nvps = null;
        try {
            nvps = ac.search(DestDef.DEST_CA_ADMIN, ScopeDef.SC_CRLIPS,
                             new NameValuePairs());
        } catch (EAdminException e) {
        }

        if (nvps != null && nvps.size() > 0) {
            Enumeration names = nvps.getNames();
            while (names.hasMoreElements()) {
                String name = (String)names.nextElement();
                if (name.indexOf('.') == -1) {
                    node = new CMSResourceObject();
                    node.setName(name);
                    CMSTabPanel crlIPTabPane = new CMSTabPanel(model, node);
                    crlIPTabPane.addTab(new CMSCRLSettingPanel(crlIPTabPane, name));
                    crlIPTabPane.addTab(new CMSCRLCachePanel(crlIPTabPane, name));
                    crlIPTabPane.addTab(new CMSCRLFormatPanel(crlIPTabPane, name));
                    node.setCustomPanel(crlIPTabPane);
                    node.setIcon( CMSAdminUtil.getImage(CMSAdminResources.IMAGE_RULEOBJECT));
                    node.setAllowsChildren(true);
                    crlsNode.add(node);

                    CMSResourceObject crlNode = node;

                    node = new CMSResourceObject("CRLEXTENSIONS");
                    CMSUGTabPanel crlExtTabPane1 = new CMSUGTabPanel(model, node);
                    crlExtTabPane1.addTab(new CRLExtensionsInstanceTab(model, DestDef.DEST_CA_ADMIN, name));
                    node.setCustomPanel(crlExtTabPane1);
                    node.setIcon( CMSAdminUtil.getImage(CMSAdminResources.IMAGE_RULEOBJECT));
                    node.setAllowsChildren(false);
                    crlNode.add(node);
                }
            }
        }

        /*backup restore sub node
        node = new CMSResourceObject("BACKUP");
        tabPane = new CMSTabPanel(model, node);
        tabPane.addTab(new CMSBlankPanel(model,tabPane,"Backup"));
        tabPane.addTab(new CMSBlankPanel(model,tabPane,"Restore"));
        node.setCustomPanel(tabPane);
        node.setIcon( CMSAdminUtil.getImage(CMSAdminResources.IMAGE_BACKUPFOLDER));
        node.setAllowsChildren(false);
        list.add(node);
        */
        
        //ldap publishing
        node = new CMSResourceObject("PUBLISHING");
        tabPane = new CMSTabPanel(model, node);
        tabPane.addTab(new CMSCALDAPPanel(tabPane));
        // tabPane.addTab(new CMSCACertSettingPanel(tabPane));
        // tabPane.addTab(new CMSUserCertSettingPanel("CAUSERCERTSETTING", tabPane));
        node.setCustomPanel(tabPane);
        node.setIcon( CMSAdminUtil.getImage(CMSAdminResources.IMAGE_LDAPPUB));
        node.setAllowsChildren(true);
        list.add(node);

        CMSResourceObject publishingNode = node;

	// allow mappers
        node = new CMSResourceObject("MAPPERS");
        CMSUGTabPanel ugtabPane = new CMSUGTabPanel(model, node);
        ugtabPane.addTab(new MapperInstanceTab(model, 
		DestDef.DEST_CA_PUBLISHER_ADMIN));
        ugtabPane.addTab(new MapperImplTab(model, 
		DestDef.DEST_CA_PUBLISHER_ADMIN));
        node.setCustomPanel(ugtabPane);
        node.setIcon(CMSAdminUtil.getImage(CMSAdminResources.IMAGE_RULEOBJECT));
        node.setAllowsChildren(false);
        publishingNode.add(node);

	// allow LDAP publisher and mapper plugins
        node = new CMSResourceObject("PUBLISHERS");
        ugtabPane = new CMSUGTabPanel(model, node);
        ugtabPane.addTab(new PublisherInstanceTab(model, 
		DestDef.DEST_CA_PUBLISHER_ADMIN));
        ugtabPane.addTab(new PublisherImplTab(model, 
		DestDef.DEST_CA_PUBLISHER_ADMIN));
        node.setCustomPanel(ugtabPane);
        node.setIcon( CMSAdminUtil.getImage(CMSAdminResources.IMAGE_RULEOBJECT));
        node.setAllowsChildren(false);
        publishingNode.add(node);

	// allow rules
        node = new CMSResourceObject("RULES");
        ugtabPane = new CMSUGTabPanel(model, node);
        ugtabPane.addTab(new RuleInstanceTab(model, 
		DestDef.DEST_CA_PUBLISHER_ADMIN));
     // XXX just support one publishing rule type
     //   ugtabPane.addTab(new RuleImplTab(model, 
     //		DestDef.DEST_CA_PUBLISHER_ADMIN));
        node.setCustomPanel(ugtabPane);
        node.setIcon(CMSAdminUtil.getImage(CMSAdminResources.IMAGE_RULEOBJECT));
        node.setAllowsChildren(false);
        publishingNode.add(node);

        
        model.addSubSystemNode(list);
    }
    
    /*
    protected void populateRepositoryContent(CMSBaseResourceModel model) {
        CMSResourceObject list, node;
        
        //ca repositories node
        list = new CMSResourceObject("CAREPOSITORIES");
        list.setCustomPanel(new CMSBlankPanel(model));
        list.setIcon( CMSAdminUtil.getImage(CMSAdminResources.IMAGE_DBCONATINER));
        list.setAllowsChildren(true);
        node = new CMSResourceObject("CAREQUESTS");
        node.setCustomPanel(new CertificateRequestPanel(model, node));
        node.setIcon( CMSAdminUtil.getImage(CMSAdminResources.IMAGE_DBOBJECT));
        node.setAllowsChildren(false);
        list.add(node);
        node = new CMSResourceObject("CACERTIFICATE");
        node.setCustomPanel(new CertificateRepositoryPanel(model,node));
        node.setIcon( CMSAdminUtil.getImage(CMSAdminResources.IMAGE_DBOBJECT));
        node.setAllowsChildren(false);
        list.add(node);
        model.addSubSystemNode(list);
    }

    protected void populateRepositoryMenu(CMSResourcePage page) {
        CMSBaseResourceModel model = (CMSBaseResourceModel) page.getModel();    
        CMSBaseMenuInfo menuInfo = (CMSBaseMenuInfo)page.getMenuInfo();
        try {
            menuInfo.registerMenuItem(CMSBaseMenuInfo.MENU_FILE,
                                      CMSBaseMenuInfo.MENU_NEWCERT,
                                      new CertRequestAction(model.getConsoleInfo(),model.getServerInfo()));            
        } catch(Exception e) {
            Debug.println("menuinfo register()"+e.toString());   
        }            
    }
    */
    protected void populateACLContent(CMSBaseResourceModel model) {
        /*
        CMSResourceObject list, node;
        list = model.getByNickName("ACL");
        node = new CMSResourceObject("CAACL");
        node.setCustomPanel(new CMSBlankPanel(model));
        node.setIcon( CMSAdminUtil.getImage(CMSAdminResources.IMAGE_DOCUMENT));
        node.setAllowsChildren(false);
        list.add(node);   
        */
    }

}
