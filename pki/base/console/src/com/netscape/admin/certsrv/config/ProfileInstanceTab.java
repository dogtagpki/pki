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
package com.netscape.admin.certsrv.config;

import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.ug.*;
import javax.swing.*;
import javax.swing.event.*;
import java.awt.event.*;
import java.awt.*;
import java.util.*;
import com.netscape.management.client.*;
import com.netscape.management.client.util.*;
import com.netscape.certsrv.common.*;

/**
 * Profile Instances Management Tab
 *
 * @author Jack Pan-Chen
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 * @see com.netscape.admin.certsrv.config
 */
public class ProfileInstanceTab extends CMSPluginInstanceTab {

    /*==========================================================
     * variables
     *==========================================================*/
    private static final String PANEL_NAME = "PROFILERULE";
    
    protected JButton mOrder;
    private final static String HELPINDEX = "configuration-certificateprofiles";
    private ResourceBundle mResource;
    private String mDest;

	/*==========================================================
     * constructors
     *==========================================================*/
    public ProfileInstanceTab(CMSBaseResourceModel model, String dest) {
        super(model,dest,PANEL_NAME);
		Debug.println("PolicyInstanceTab::PolicyInstanceTab(<model>,"+dest);
        mConnection = model.getServerInfo().getAdmin();
        mDataModel = new ProfileRuleDataModel();
		mScope = ScopeDef.SC_POLICY_RULES;
        mDest = dest;
		RULE_NAME = PolicyRuleDataModel.RULE_NAME;
	  	RULE_STAT = PolicyRuleDataModel.RULE_STAT;  
        mResource = ResourceBundle.getBundle(
          CMSAdminResources.class.getName());

        mHelpToken = HELPINDEX;
    }

	public CMSBaseConfigDialog makeEditConfigDialog(
			NameValuePairs nvp,
			JFrame parent,
			AdminConnection conn,
			String dest
			) 
	{
		return new ProfileEditDialog(nvp,
			parent,
			conn,
			dest);
	}

	public CMSBaseConfigDialog makeNewConfigDialog(
			NameValuePairs nvp,
			JFrame parent,
			AdminConnection conn,
			String dest
			) 
	{

		return new ProfileConfigDialog(nvp,
			parent,
			conn,
			dest);
	}

	public PluginSelectionDialog getPluginSelectionDialog(
			JFrame parent,
			AdminConnection conn,
			String dest,
			CMSPluginInstanceTab pluginType
			) 
	{
		return new ProfilePluginSelectionDialog(parent,conn,DestDef.DEST_REGISTRY_ADMIN, dest, pluginType);
	}


    //=== ACTIONLISTENER =====================
    public void actionPerformed(ActionEvent e) {
      if (e.getSource().equals(mEdit) || e.getSource().equals(mDelete)) {
          if(mTable.getSelectedRow()< 0) 
              return; 
          NameValuePairs data = (NameValuePairs) 
            mDataModel.getObjectValueAt(mTable.getSelectedRow());
          // dont check enable and disable here.  We want to
          // view profile even though it is enabled
      }

      super.actionPerformed(e);
    }

    public void moreActionPerformed(ActionEvent e) {
        if (e.getSource().equals(mOrder)) {
            Debug.println("Order");
            PolicyRuleOrderDialog dialog = 
                new PolicyRuleOrderDialog(mModel.getFrame(), 
                            mConnection, mDestination);
            dialog.showDialog(mDataModel.getRules());  
            refresh();
        }        
    }

    /**
     * create the user action button panel
     */
    protected JPanel createUserButtonPanel() {
        //edit, add, delete, help buttons required
        //actionlister to this object
        mOrder = makeJButton("ORDER");
        mEdit = makeJButton("EDIT");
        mAdd = makeJButton("ADD");
        mDelete = makeJButton("DELETE");
		JButton[] buttons = {mAdd, mDelete, mEdit };
		JButtonFactory.resize( buttons );
		return CMSAdminUtil.makeJButtonVPanel( buttons );
    }


    //set buttons
    protected void setButtons() {
		super.setButtons();
        
        if (mDataModel.getRowCount()<=0) {
		    mOrder.setEnabled(false);
		}
		else {
	    	mOrder.setEnabled(true);
		}
    }
    
   
}
