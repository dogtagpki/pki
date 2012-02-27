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
import javax.swing.*;
import java.awt.event.*;

import com.netscape.management.client.util.*;
import com.netscape.certsrv.common.*;

/**
 * Policy Plugin Selection Dialog
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config
 */
public class ProfilePluginSelectionDialog extends PluginSelectionDialog
{
    /*==========================================================
     * variables
     *==========================================================*/
    private static final String PREFIX = "PROFILESELECTIONDIALOG";
    private static final String HELPINDEX = "configuration-certificateprofiles";

    /*==========================================================
     * constructors
     *==========================================================*/
    public ProfilePluginSelectionDialog(
			JFrame parent,
			AdminConnection conn, 
			String dest,
			CMSPluginInstanceTab pluginType) 
	{
        super(PREFIX, parent,conn, dest, pluginType);
        mScope         = ScopeDef.SC_PROFILE_IMPLS;
        mInstanceScope = ScopeDef.SC_PROFILE_RULES;
        mImageName     = CMSAdminResources.IMAGE_RULE_PLUGIN;
        mHelpToken = HELPINDEX;
        mDataModel = new ProfileListDataModel();
        setDisplay();
    }

    public ProfilePluginSelectionDialog(
                        JFrame parent,
                        AdminConnection conn,
                        String dest, String extraDest,
                        CMSPluginInstanceTab pluginType)
        {
        super(PREFIX, parent,conn, dest, extraDest, pluginType);
        mScope         = ScopeDef.SC_PROFILE_IMPLS;
        mInstanceScope = ScopeDef.SC_PROFILE_RULES;
        mImageName     = CMSAdminResources.IMAGE_RULE_PLUGIN;
        mHelpToken = HELPINDEX;
        mDataModel = new ProfileListDataModel();
        setDisplay();
    }

    public void actionPerformed(ActionEvent evt) {

        if (evt.getSource().equals(mOK)) {
            NameValuePairs response;
            try {
                response = getDefaultConfig();
            } catch (EAdminException e) {
                CMSAdminUtil.showErrorDialog(mParentFrame, mResource,
                    e.getMessage(), CMSAdminUtil.ERROR_MESSAGE);
                return;
            }
            Debug.println(response.toString());
            String id =(String)(((ProfileListDataModel)mDataModel).getObjectValueAt(mList.getSelectedIndex()));
            response.put(Constants.PR_POLICY_IMPL_NAME, id);

            CMSBaseConfigDialog dialog = null;
            if (mExtraDestination == null) {
                dialog = mPluginInstanceDialog.makeNewConfigDialog(
                  response, mParentFrame, mConnection, mDestination);
            } else  {
                dialog = mPluginInstanceDialog.makeNewConfigDialog(
                  response, mParentFrame, mConnection, mExtraDestination);
            }

            dialog.setModel(mModel);
            dialog.setInstanceScope(mInstanceScope);

            dialog.showDialog(response,"");

            if(!dialog.isOK()) {
                this.dispose();
                return;
            }

            response = dialog.getData();
            String name = dialog.getRuleName();

            Debug.println(response.toString());

            dialog.dispose();
            this.dispose();
        }


        if (evt.getSource().equals(mCancel)) {
            this.dispose();
        }
        if (evt.getSource().equals(mHelp)) {
            CMSAdminUtil.help(mHelpToken);
        }
    }

    //this returns the default configuration
    protected NameValuePairs getDefaultConfig() throws EAdminException {
        String id = (String)(((ProfileListDataModel)mDataModel).getObjectValueAt(mList.getSelectedIndex()));
        NameValuePairs response;
        response = mConnection.read(mDestination, mScope, id,
          new NameValuePairs());

        Debug.println(response.toString());

        return response;
    }

    //save order information to the server
    protected boolean update() {

        NameValuePairs response;
        try {
            response = mConnection.search(mDestination, mScope,
                               new NameValuePairs());
        } catch (EAdminException e) {
            //display error dialog
            CMSAdminUtil.showErrorDialog(mParentFrame, mResource,
                e.getMessage(), CMSAdminUtil.ERROR_MESSAGE);
            return false;
        }

        Debug.println(response.toString());

        //parse the data
        String[] classnames = new String[response.size()];
        String[] ids = new String[response.size()];
        int i=0;
        for (String id : response.keySet()) {
            String value = response.get(id);
            int pos = value.lastIndexOf(",");
            String className = value.substring(pos+1);

            classnames[i] = className;
            ids[i++] = id;
            Debug.println("PluginSelectionDialog::update() - adding '"+classnames[i-1]+"'");
        }

        CMSAdminUtil.bubbleSort(classnames, ids);

        for (int y=0; y< classnames.length ; y++) {
            try {
            ((ProfileListDataModel)mDataModel).addElement(new JLabel(classnames[y],
              CMSAdminUtil.getImage(mImageName), JLabel.LEFT), ids[y]);
            }
            catch (Exception ex) {
                Debug.println("PluginSelectionDialog could not get image for '"+
                    mImageName+"'. Adding without image");
            ((ProfileListDataModel)mDataModel).addElement(new JLabel(classnames[y],
              JLabel.LEFT), ids[y]);
            }
        }

        return true;
    }
}
