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

import java.awt.event.ActionEvent;

import com.netscape.admin.certsrv.EAdminException;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.DestDef;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.common.ScopeDef;
import com.netscape.management.client.util.Debug;

/**
 * Access Log Setting Tab to be displayed at the right hand side
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @deprecated The PKI console will be removed once there are CLI equivalents of desired console features.
 */
@Deprecated(since="10.14.0", forRemoval=true)
public class CMSAccessLogPanel extends CMSBaseLogPanel {
    /*==========================================================
     * variables
     *==========================================================*/
    private static String PANEL_NAME = "ACCESSLOG";
    private CMSTabPanel mParent;
    private static final String HELPINDEX = "configuration-logs-system-help";

    /*==========================================================
     * constructors
     *==========================================================*/
    public CMSAccessLogPanel(CMSTabPanel parent, boolean isNT) {
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
        Debug.println("AccessLogPanel: init()");
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
              ScopeDef.SC_SYSTEMLOG, Constants.RS_ID_CONFIG, nvp);
            parseVals(val);
            if (mIsNT) {
                nvp.clear();
                nvp.put(Constants.PR_NT_EVENT_SOURCE, "");
                nvp.put(Constants.PR_NT_LOG_LEVEL, "");
                nvp.put(Constants.PR_NT_LOG_ENABLED, "");
                val = mAdmin.read(DestDef.DEST_LOG_ADMIN,
                  ScopeDef.SC_NTSYSTEMLOG, Constants.RS_ID_CONFIG, nvp);
                parseNTVals(val);
            }
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

    private void parseNTVals(NameValuePairs nvp) {
        mNTLevel = Integer.parseInt(nvp.get(Constants.PR_NT_LOG_LEVEL));
        mSource = nvp.get(Constants.PR_NT_EVENT_SOURCE);
        if (nvp.get(Constants.PR_NT_LOG_ENABLED).equalsIgnoreCase(
          Constants.TRUE))
            mActivateNTLog.setSelected(true);
        else
            mActivateNTLog.setSelected(false);
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
        mModel.progressStart();
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

        try {
            mAdmin.modify(DestDef.DEST_LOG_ADMIN,
              ScopeDef.SC_SYSTEMLOG, Constants.RS_ID_CONFIG, nvp);
            if (mIsNT) {
                nvp.clear();
                nvp.put(Constants.PR_NT_LOG_LEVEL,
                        "" + mNTLogLevel.getSelectedIndex());
                nvp.put(Constants.PR_NT_EVENT_SOURCE,
                        mEventSourceText.getText().trim());
                if (mActivateNTLog.isSelected())
                    nvp.put(Constants.PR_NT_LOG_ENABLED, Constants.TRUE);
                else
                    nvp.put(Constants.PR_NT_LOG_ENABLED, Constants.FALSE);
                mAdmin.modify(DestDef.DEST_LOG_ADMIN,
                  ScopeDef.SC_NTSYSTEMLOG, Constants.RS_ID_CONFIG, nvp);
            }
        } catch (EAdminException e) {
            showErrorDialog(e.toString());
            mModel.progressStop();
            return false;
        }

        clearDirtyFlag();
        mModel.progressStop();
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
