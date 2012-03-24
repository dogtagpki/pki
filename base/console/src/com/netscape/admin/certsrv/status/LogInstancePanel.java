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
package com.netscape.admin.certsrv.status;


import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.*;
import com.netscape.certsrv.common.*;
import com.netscape.management.client.util.*;

import java.awt.event.*;

/**
 * Transactions Log Panel to be displayed at the right hand side
 *
 * @author Jack Pan-Chen
 * @author Michelle Zhao
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.status
 */
public class LogInstancePanel extends CMSLogPanel {

    /*==========================================================
     * variables
     *==========================================================*/
    private String mSelectedFile;
    private String mInstanceName;
    private static final String HELPINDEX = "status-logs-help";
    private static final String AUDITHELPINDEX = "status-logs-audit-help";
    private static final String SYSTEMHELPINDEX = "status-logs-system-help";
    private static final String ERRORHELPINDEX = "status-logs-error-help";

    /*==========================================================
     * constructors
     *==========================================================*/
    public LogInstancePanel(CMSBaseResourceModel model) {
        super(model, new LogDataModel());
        mHelpToken = HELPINDEX;
    }

    public LogInstancePanel(String name, CMSBaseResourceModel model) {
        super(model, new LogDataModel());
		mInstanceName = name;
		// xxx this is temperary
		if (name.equals("transactions"))
			mHelpToken = AUDITHELPINDEX;
		else if (name.equals("system"))
			mHelpToken = SYSTEMHELPINDEX;
		else if (name.equals("error"))
			mHelpToken = ERRORHELPINDEX;
		else 
			mHelpToken = HELPINDEX;
    }

    /**
     * retrieve data and process it
     */
    protected void update() {
         AdminConnection connection = mModel.getServerInfo().getAdmin();

        //construct NVP
        NameValuePairs config = new NameValuePairs();
        config.put(Constants.PR_LOG_INSTANCE, mInstanceName);
        config.put(Constants.PR_LOG_ENTRY, mNoRecord.getText().trim());
        config.put(Constants.PR_LOG_SOURCE, Integer.toString(mSource.getSelectedIndex()));
        config.put(Constants.PR_LOG_LEVEL, Integer.toString(mLevel.getSelectedIndex()));
        if ((mFile.getSelectedIndex()< 0) || (mFile.getSelectedIndex()< 0)) {
            config.put(Constants.PR_LOG_NAME, Constants.PR_CURRENT_LOG);
            mSelectedFile = mResource.getString("LOGCONTENT_COMBOBOX_FILE_DEFAULT");
        } else {
            String filename = (String) mFile.getSelectedItem();
            if (filename.equalsIgnoreCase(Constants.PR_CURRENT_LOG))
                filename = Constants.PR_CURRENT_LOG;
            config.put(Constants.PR_LOG_NAME, filename);
            mSelectedFile = (String) mFile.getSelectedItem();
        }
        NameValuePairs response;
        mModel.progressStart();
        try {
            response = connection.search(DestDef.DEST_LOG_ADMIN,
                               ScopeDef.SC_LOG_CONTENT,
                               config);
        } catch (EAdminException e) {
            //display error dialog
            showErrorDialog(e.getMessage());
            mModel.progressStop();
            return;
        }

        mModel.progressStop();
        Debug.println(response.toString());

        //update the table
        for (String entry : response.keySet()) {
            mDataModel.processData(entry);
        }

        updateArchive();
    }

    /**
     * retrieve archieve log file listing from the server
     * side and poupulate the combobox
     */
    protected void updateArchive() {
        AdminConnection connection = mModel.getServerInfo().getAdmin();
        String value = mResource.getString("LOGCONTENT_COMBOBOX_FILE_DEFAULT");
        mFile.removeAllItems();
        mFile.addItem(value);

        //get stuff
        NameValuePairs response;
        mModel.progressStart();
        //construct NVP
        NameValuePairs config = new NameValuePairs();
        config.put(Constants.PR_LOG_INSTANCE, mInstanceName);
        try {
            response = connection.search(DestDef.DEST_LOG_ADMIN,
                               ScopeDef.SC_LOG_ARCH,
                               config);
        } catch (EAdminException e) {
            //display error dialog
            showErrorDialog(e.getMessage());
            mModel.progressStop();
            return;
        }

        //update the combo
        for (String entry : response.keySet()) {
            mFile.addItem(entry);
        }
        mModel.progressStop();
        mFile.setSelectedItem(mSelectedFile);
    }

    public void actionPerformed(ActionEvent e) {
        super.actionPerformed(e);
        if (e.getSource().equals(mHelp)) {
            CMSAdminUtil.help(mHelpToken);
        }
    }
}
