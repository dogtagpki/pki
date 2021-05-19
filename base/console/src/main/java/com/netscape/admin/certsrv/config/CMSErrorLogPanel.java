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
import com.netscape.certsrv.common.*;
import com.netscape.management.client.util.*;

import java.awt.event.*;

/**
 * Error Log Setting Tab to be displayed at the right hand side
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 */
public class CMSErrorLogPanel extends CMSBaseLogPanel {

    /*==========================================================
     * variables
     *==========================================================*/
    private static String PANEL_NAME = "ERRORLOG";
    private CMSTabPanel mParent;
    private static final String HELPINDEX = "configuration-logs-error-help";

    /*==========================================================
     * constructors
     *==========================================================*/
    public CMSErrorLogPanel(CMSTabPanel parent, boolean isNT) {
        super(PANEL_NAME, parent);
        mParent = parent;
        mHelpToken = HELPINDEX;
        mIsNT = isNT;
    }

    /*==========================================================
	 * public methods
     *==========================================================*/

    /**
     * Actual Instantiation of the UI components
     */
    @Override
    public void init() {
        Debug.println("ErrorLogPanel: init()");
        super.init();
        refresh();
    }

    @Override
    public void refresh() {
        mModel.progressStart();
        NameValuePairs nvp = new NameValuePairs();
        nvp.put(Constants.PR_LOG_ENABLED, "");
        nvp.put(Constants.PR_LOG_LEVEL, "");
        nvp.put(Constants.PR_LOG_BUFFERSIZE, "");
        //nvp.add(Constants.PR_LOG_EXPIRED_TIME, "");
        //nvp.add(Constants.PR_LOG_FILENAME, "");
        //nvp.add(Constants.PR_LOG_FLUSHINTERVAL, "");
        nvp.put(Constants.PR_LOG_MAXFILESIZE, "");
        nvp.put(Constants.PR_LOG_ROLLEROVER_INTERVAL, "");

        try {
            NameValuePairs val = mAdmin.read(DestDef.DEST_LOG_ADMIN,
              ScopeDef.SC_ERRORLOG, Constants.RS_ID_CONFIG, nvp);

            parseVals(val);
        } catch (EAdminException e) {
            showErrorDialog(e.toString());
            mModel.progressStop();
        }
        setValues();
        mModel.progressStop();
        clearDirtyFlag();
        mParent.setOKCancel();
    }

    private void parseVals(NameValuePairs nvp) {
        if (nvp.get(Constants.PR_LOG_ENABLED).equalsIgnoreCase(
            Constants.TRUE))
            activateLog.setSelected(true);
        else
            activateLog.setSelected(false);
        mLevel = Integer.parseInt(nvp.get(Constants.PR_LOG_LEVEL));
        mlogBufSizTextData = nvp.get(Constants.PR_LOG_BUFFERSIZE);
        mlogMaxSizTextData = nvp.get(Constants.PR_LOG_MAXFILESIZE);
        int val =
          Integer.parseInt(nvp.get(Constants.PR_LOG_ROLLEROVER_INTERVAL));
        mFrequency = getRollOverIndex(val);
    }

	/**
	 * Implementation for saving panel information
	 * @return true if save successful; otherwise, false.
	 */
    @Override
    public boolean applyCallback() {
        // check blank fields
        if ((mlogMaxSizText.getText().trim().equals("")) ||
             (mlogBufSizText.getText().trim().equals("")) ) {
             showMessageDialog("BLANKFIELD");
             return false;
        }

        String bufSize = mlogBufSizText.getText().trim();
        String maxSize = mlogMaxSizText.getText().trim();

        try {
            int val1 = Integer.parseInt(bufSize);
            int val2 = Integer.parseInt(maxSize);
            if (val1 <= 0 || val2 <= 0) {
                showMessageDialog("OUTOFRANGE");
                return false;
            }
        } catch (NumberFormatException e) {
            showMessageDialog("NUMBERFORMAT");
            return false;
        }

        NameValuePairs nvp = new NameValuePairs();

        if (activateLog.isSelected())
            nvp.put(Constants.PR_LOG_ENABLED, Constants.TRUE);
        else
            nvp.put(Constants.PR_LOG_ENABLED, Constants.FALSE);
        String str = "" + mLogLevel.getSelectedIndex();
        nvp.put(Constants.PR_LOG_LEVEL, str);
        nvp.put(Constants.PR_LOG_BUFFERSIZE, mlogBufSizText.getText().trim());
        //nvp.add(Constants.PR_LOG_EXPIRED_TIME, "");
        //nvp.add(Constants.PR_LOG_FILENAME, "");
        //nvp.add(Constants.PR_LOG_FLUSHINTERVAL, "");
        nvp.put(Constants.PR_LOG_MAXFILESIZE, mlogMaxSizText.getText().trim());

        str = "" + getRollOverTime(mlogFQC.getSelectedIndex());
        nvp.put(Constants.PR_LOG_ROLLEROVER_INTERVAL, str);

        mModel.progressStart();
        try {
            mAdmin.modify(DestDef.DEST_LOG_ADMIN,
              ScopeDef.SC_ERRORLOG, Constants.RS_ID_CONFIG, nvp);
        } catch (EAdminException e) {
            showErrorDialog(e.toString());
            mModel.progressStop();
            return false;
        }
        mModel.progressStop();
        clearDirtyFlag();
        return true;
    }

    /**
     * Implementation for reset values
     * @return true if save successful; otherwise, false.
     */
    @Override
    public boolean resetCallback() {
        refresh();
        return true;
    }

	/*==========================================================
	 * EVENT HANDLER METHODS
     *==========================================================*/

    //=== ACTIONLISTENER =====================
    @Override
    public void actionPerformed(ActionEvent e) {
		super.actionPerformed(e);
	}
}
