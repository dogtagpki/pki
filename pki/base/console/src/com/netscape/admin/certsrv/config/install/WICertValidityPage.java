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
package com.netscape.admin.certsrv.config.install;

import java.awt.*;
import java.util.*;
import java.text.*;
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.certsrv.common.*;
import com.netscape.admin.certsrv.config.*;
import com.netscape.admin.certsrv.task.*;
import com.netscape.management.client.console.*;

/**
 * Validity page for installation wizard
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WICertValidityPage extends WBaseValidityPage implements IWizardPanel {
    private String mPanelName;
    protected String mHelpIndex;
    
    WICertValidityPage(String panelName) {
        super(panelName);
        mPanelName = panelName;
        init();
    }

    public boolean isLastPage() {
        return false;
    }

    public boolean initializePanel(WizardInfo info) {
        setBorder(makeTitledBorder(mPanelName));
        return true;
    }

    public void callHelp() {
        CMSAdminUtil.help(mHelpIndex);
    }

    protected void init() {
        super.init();
    }

    public boolean validatePanel() {
        boolean status = super.validatePanel();
        Date currTime = new Date();

        if (status) {
            if (currTime.before(mBeforeDate)) {
                if (!mWarningDisplayed) {
                    setErrorMessage("INVALIDCERT");
                    mWarningDisplayed = true;
                    return false;
                }
            }
        }

        return status;
    }

    public boolean concludePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        if (!wizardInfo.getCertType().equals(Constants.PR_CA_SIGNING_CERT)) {
            String rawData = ConfigConstants.TASKID+"="+TaskId.TASK_VALIDITY_PERIOD;
            rawData = rawData+"&"+ConfigConstants.OPTYPE+"="+OpDef.OP_MODIFY;
            rawData = rawData+"&"+ConfigConstants.PR_NOTAFTER+"="+mAfterDate.getTime();
            startProgressStatus();
            boolean ready = send(rawData, wizardInfo);
            endProgressStatus();

            if (!ready) {
                String str = getErrorMessage(wizardInfo);
                if (str.equals("")) {
                    String errorMsg = mResource.getString(
                      mPanelName+"_ERRORMSG");
                    setErrorMessage(errorMsg);
                } else if (str.equals("beyondCAValidity")) {
                    String errormsg = mResource.getString(mPanelName+"_BEYONDCAVALIDITY");
                    int status = JOptionPane.showConfirmDialog(mAdminFrame, errormsg, "Information",
                      JOptionPane.OK_CANCEL_OPTION, JOptionPane.INFORMATION_MESSAGE,
                      CMSAdminUtil.getImage(CMSAdminResources.IMAGE_INFO_ICON));
                    if (status == JOptionPane.OK_OPTION) {
                        rawData = rawData+"&"+ConfigConstants.OVERRIDE_VALIDITY+"="+ConfigConstants.TRUE;
                        ready = send(rawData, wizardInfo);
                        return true;
                    } else {
                        setErrorMessage(mResource.getString(mPanelName+"_ERROR1"));
                        return false;
                    }
                } else 
                    setErrorMessage(str);
                return ready;
            }
        }

        return super.concludePanel(info);
    }

    public void getUpdateInfo(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        wizardInfo.addEntry(Constants.PR_BEGIN_YEAR, mBYear.getText().trim());
        int beforeMonth = Integer.parseInt(mBMonth.getText().trim());
        wizardInfo.addEntry(Constants.PR_BEGIN_MONTH, ""+(beforeMonth-1));
        wizardInfo.addEntry(Constants.PR_BEGIN_DATE, mBDay.getText().trim());
        wizardInfo.addEntry(Constants.PR_BEGIN_HOUR, mBHour.getText().trim());
        wizardInfo.addEntry(Constants.PR_BEGIN_MIN, mBMin.getText().trim());
        wizardInfo.addEntry(Constants.PR_BEGIN_SEC, mBSec.getText().trim());
        wizardInfo.addEntry(Constants.PR_AFTER_YEAR, mEYear.getText().trim());
        int afterMonth = Integer.parseInt(mEMonth.getText().trim());
        wizardInfo.addEntry(Constants.PR_AFTER_MONTH, ""+(afterMonth-1));
        wizardInfo.addEntry(Constants.PR_AFTER_DATE, mEDay.getText().trim());
        wizardInfo.addEntry(Constants.PR_AFTER_HOUR, mEHour.getText().trim());
        wizardInfo.addEntry(Constants.PR_AFTER_MIN, mEMin.getText().trim());
        wizardInfo.addEntry(Constants.PR_AFTER_SEC, mESec.getText().trim());
        //wizardInfo.addEntry(Constants.PR_VALIDITY_PERIOD, ""+period);
    }
}
