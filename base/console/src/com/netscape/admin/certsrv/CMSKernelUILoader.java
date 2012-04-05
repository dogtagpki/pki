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
import com.netscape.management.client.console.*;
import com.netscape.admin.certsrv.security.*;
import com.netscape.admin.certsrv.menu.*;
import com.netscape.admin.certsrv.config.*;
import com.netscape.admin.certsrv.ug.*;
import com.netscape.admin.certsrv.status.*;
import com.netscape.certsrv.common.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.CMSUIFramework;
import java.util.*;
import javax.swing.*;

/**
 * Netscape Certificate Server Kernel UI Loader.
 *
 * This class registers tabs (tasks,configuraiton,status)
 * into the UI framework.
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @date        03/30/97
 */
public class CMSKernelUILoader implements ISubSystemUILoader {

    protected static final int ERROR_MESSAGE = JOptionPane.ERROR_MESSAGE;
    /*==========================================================
     * variables
     *==========================================================*/
    private CMSUIFramework mUIFramework;      //parent framework

    /*==========================================================
     * constructors
     *==========================================================*/
    public CMSKernelUILoader(CMSUIFramework framework) {
        mUIFramework = framework;
    }

    /*==========================================================
     * public methods
     *==========================================================*/
    public void register() {

        //register subsystem UI
        try {
            //task tab - this holds icons such as start server, stop server, etc
            IPage task = mUIFramework.getPage(CMSPageFeeder.TASK_TAB_TYPE,"");
        }catch(Exception e) {
            Debug.println("CMSKernelUILoader: register() config tab - "+e.toString());
        }
        CMSResourcePage page;
        CMSBaseResourceModel model;

        try {
            //configuration tab - (holds main UI tree)
            page = (CMSResourcePage) mUIFramework.getPage(CMSPageFeeder.RESOURCE_TAB_TYPE,"CONFIGURATION");
            model = (CMSBaseResourceModel) page.getModel();
            populateConfigContent(model);
            populateConfigMenu(page);

        } catch(Exception e) {
            Debug.println("CMSKernelUILoader: register() config tab - "+e.toString());
        }

        try {
            //status tab - allows user to view CMS log files
            page = (CMSResourcePage) mUIFramework.getPage(CMSPageFeeder.RESOURCE_TAB_TYPE,"STATUS");
            populateStatusContent(page);
            populateStatusMenu(page);
        } catch(Exception e) {
            Debug.println("CMSKernelUILoader: register() status - "+e.toString());
        }
    }

    /*==========================================================
     * protected methods
     *==========================================================*/

    /**
     * This method creates the configuration tree
     */

    protected void populateConfigContent(CMSBaseResourceModel model) {

        CMSResourceObject root = (CMSResourceObject) model.getRoot();
        CMSTabPanel tabPane = new CMSTabPanel(model, root);
        tabPane.addTab(new CMSLDAPSettingPanel(tabPane));
        tabPane.addTab(new CMSSMTPPanel(tabPane));
        tabPane.addTab(new CMSSelfTestsPanel(tabPane));

        // The log panel would only really be useful if we were able to
        // enable or disable debug without restarting.  If we can do this,
        // then we can enable this tab.
        //
        // tabPane.addTab(new GeneralLogPanel(tabPane));

        root.setCustomPanel(tabPane);


        CMSResourceObject usernode = new CMSResourceObject("USERGROUPS");
        CMSUGTabPanel tabPane1 = new CMSUGTabPanel(model, usernode);
        tabPane1.addTab(new UserTab(model));
        tabPane1.addTab(new GroupTab(model));
        usernode.setCustomPanel(tabPane1);
        usernode.setAllowsChildren(false);
        usernode.setIcon(CMSAdminUtil.getImage(CMSAdminResources.IMAGE_UGOBJECT));
        model.addSubSystemNode(usernode);

// This ACL configuration may be revived in a future version
        CMSResourceObject aclnode = new CMSResourceObject("ACL");
        CMSUGTabPanel aclTabPane = new CMSUGTabPanel(model, aclnode);
        aclTabPane.addTab(new ACLPanel(aclTabPane));
        aclTabPane.addTab(new ACLImplTab(aclTabPane));
        aclnode.setCustomPanel(aclTabPane);
        aclnode.setIcon(CMSAdminUtil.getImage(
          CMSAdminResources.IMAGE_ACLOBJECT));
        aclnode.setAllowsChildren(false);
        model.addSubSystemNode(aclnode);

	// Authentication subsystem
/*
        CMSResourceObject authnode = new CMSResourceObject("AUTH");
        tabPane1 = new CMSUGTabPanel(model, authnode);
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
*/

        // log config node
        CMSResourceObject node = new CMSResourceObject("LOG");

        CMSUGTabPanel tabPane2 = new CMSUGTabPanel(model, node);
        tabPane2.addTab(new LogInstanceTab(model, DestDef.DEST_LOG_ADMIN));
        tabPane2.addTab(new LogImplTab(model, DestDef.DEST_LOG_ADMIN));
        node.setCustomPanel(tabPane2);
        node.setIcon( CMSAdminUtil.getImage(CMSAdminResources.IMAGE_LOGOBJ));
        node.setAllowsChildren(false);
        model.addSubSystemNode(node);

        // encryption config node
        CMSResourceObject encryptionnode = new CMSResourceObject("ENCRYPTION");
        CMSUGTabPanel tabPane3 = new CMSUGTabPanel(model, encryptionnode);
        tabPane3.addTab(new CACertsTab(model, DestDef.DEST_SERVER_ADMIN));
        tabPane3.addTab(new UserCertsTab(model, DestDef.DEST_SERVER_ADMIN));
        NameValuePairs response;
/*
        try
        {
        AdminConnection connection = model.getServerInfo().getAdmin();

        response = connection.search(DestDef.DEST_SERVER_ADMIN,
                   ScopeDef.SC_SUBSYSTEM,  new NameValuePairs());
         Debug.println(response.toString());
         String tempString =  response.toString();
         if(tempString.length()==0) // tempString should equals tks=tks in CMSAdminServlet::readSubsystem
            tabPane3.addTab(new TKSKeysTab(model, DestDef.DEST_SERVER_ADMIN));
       }catch (Exception e) {
            Debug.println("bad admin servlet connection ");
        }
*/

        encryptionnode.setCustomPanel(tabPane3);
        encryptionnode.setIcon( CMSAdminUtil.getImage(CMSAdminResources.IMAGE_AUTHOBJECT));
        encryptionnode.setAllowsChildren(false);
        model.addSubSystemNode(encryptionnode);
    }


    /**
     * Modifies the window menu (File, Edit, View, etc) to add some
     * things which are specific to CMS configuration
     */
    protected void populateConfigMenu(CMSResourcePage page) {
        CMSBaseResourceModel model = (CMSBaseResourceModel) page.getModel();
        CMSBaseMenuInfo menuInfo = (CMSBaseMenuInfo)page.getMenuInfo();
        try {
            //menuInfo.registerMenuItem(CMSBaseMenuInfo.MENU_FILE,
            //                          CMSBaseMenuInfo.MENU_PKCS11,
            //                          new PKCS11ManagementAction(model.getConsoleInfo()));
            // reference Bug 613851 Manage PKCS#11 shows a blank window.
            menuInfo.addMenuItemSeparator(CMSBaseMenuInfo.MENU_FILE);
            menuInfo.addMenuItemSeparator(CMSBaseMenuInfo.MENU_VIEW);
            menuInfo.registerMenuItem(CMSBaseMenuInfo.MENU_VIEW,
                                      CMSBaseMenuInfo.MENU_REFRESH,
                                      new RefreshTabPane(model));
        } catch(Exception e) {
            Debug.println("menuinfo register()"+e.toString());
        }
    }


    /**
     * creates the tree view seen in the left panel when the user selects
     * the status tab. This typically looks like this:
     * 1 Netscape Certificate Management System
     * 2   + Log
     * 3        System
     * 4        Transactions
     *   [ this method creates 1,2. The updateLogInstance() method creates 3,4 ]
     */

    protected void populateStatusContent(CMSResourcePage page) {
        CMSBaseResourceModel model = (CMSBaseResourceModel) page.getModel();
        CMSResourceObject root = (CMSResourceObject) model.getRoot();

        //set general stat panel
        root.setCustomPanel(new StatusPanel(model));

        CMSResourceObject list, node;
        CMSTabPanel tabPane;

        //log content
        list = new CMSResourceObject("LOG");
        list.setCustomPanel(new CMSBlankPanel(model));
        list.setIcon( CMSAdminUtil.getImage(CMSAdminResources.IMAGE_LOGFOLDER));
        list.setAllowsChildren(true);

	// get the log instance name list
	updateLogInstance(page, list);

        model.addSubSystemNode(list);
    }

    protected void populateStatusMenu(CMSResourcePage page) {
        CMSBaseResourceModel model = (CMSBaseResourceModel) page.getModel();
        CMSBaseMenuInfo menuInfo = (CMSBaseMenuInfo)page.getMenuInfo();
        try {
            menuInfo.addMenuItemSeparator(CMSBaseMenuInfo.MENU_VIEW);
            menuInfo.registerMenuItem(CMSBaseMenuInfo.MENU_VIEW,
                                      CMSBaseMenuInfo.MENU_REFRESH,
                                      new RefreshTabPane(model));
        } catch(Exception e) {
            Debug.println("menuinfo register()"+e.toString());
        }
    }

    /**
     * retrieve log instance listing from the server
     * side and populate the index
     */
    protected void updateLogInstance(CMSResourcePage page, CMSResourceObject list) {
        CMSBaseResourceModel model = (CMSBaseResourceModel) page.getModel();
        AdminConnection connection = model.getServerInfo().getAdmin();

        //get the list of log instances from the server
        NameValuePairs response;
        model.progressStart();
        try {
            response = connection.search(DestDef.DEST_LOG_ADMIN,
                               ScopeDef.SC_LOG_INSTANCES,
                               new NameValuePairs());
        } catch (EAdminException e) {
            //display error dialog
			CMSAdminUtil.showErrorDialog(model.getFrame(),
				ResourceBundle.getBundle(
					CMSAdminResources.class.getName()
					), e.getMessage(), ERROR_MESSAGE);
            model.progressStop();
            return;
        }

        //update the index
        for (String entry : response.keySet()) {
			CMSResourceObject node = new CMSResourceObject(entry);
			node.setCustomPanel(new LogInstancePanel(entry, model));
			node.setIcon( CMSAdminUtil.getImage(CMSAdminResources.IMAGE_LOGOBJECT));
			node.setAllowsChildren(false);
			list.add(node);
        }
        model.progressStop();
    }

}
