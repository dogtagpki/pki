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
import javax.swing.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.certsrv.common.*;
import com.netscape.admin.certsrv.task.*;
import com.netscape.management.client.console.*;

/**
 * Generate the certificate
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.keycert
 */
class WIGenKeyCertPage extends WizardBasePanel implements IWizardPanel {
    private JTextArea desc;
    private String mPanelName;
    protected String mHelpIndex;
    
    WIGenKeyCertPage(String panelName) {
        super(panelName);
        mPanelName = panelName;
        init();
    }

    public boolean isLastPage() {
        return false;
    }

    public boolean initializePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        setBorder(makeTitledBorder(mPanelName));

        String str = mResource.getString(mPanelName+"_TEXT_NEWKEY_LABEL");
        desc.setText(str);
        return true; 
    }

    public boolean validatePanel() {
        return true;
    }

    public boolean concludePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        NameValuePairs nvps = wizardInfo.getAllCertInfo();
        String rawData = ConfigConstants.TASKID+"="+TaskId.TASK_CREATE_CERT;
        rawData = rawData+"&"+ConfigConstants.OPTYPE+"="+OpDef.OP_MODIFY;
        rawData = rawData+"&"+ConfigConstants.PR_HASH_TYPE+"="+wizardInfo.getHashType();
        if (wizardInfo.getCertType().equals(Constants.PR_CA_SIGNING_CERT)) {
            String OComp = wizardInfo.getCAOComp();
            if (OComp != null && !OComp.equals("")) {
                rawData = rawData+"&"+ConfigConstants.PR_CA_O_COMPONENT+"="+
                  wizardInfo.getCAOComp();
            }
            String CComp = wizardInfo.getCACComp();
            if (CComp != null && !CComp.equals(""))
                rawData = rawData+"&"+ConfigConstants.PR_CA_C_COMPONENT+"="+
                  wizardInfo.getCACComp();
        }

        // testing, please remove after finish testing
        if (wizardInfo.getInternalDBPasswd() != null)
            rawData = rawData+"&"+ConfigConstants.PR_DB_PWD+"="+wizardInfo.getInternalDBPasswd();

	if (nvps != null) {
        	for (int i=0; i<nvps.size(); i++) {
        	    NameValuePair nvp = (NameValuePair)nvps.elementAt(i);
                    rawData = rawData+"&"+nvp.getName()+"="+nvp.getValue();
        	}
	}
        
        startProgressStatus();
        
        //CMSMessageBox dlg = new CMSMessageBox(mAdminFrame, "CGITASK", "CREATECERT");
        
        boolean ready = send(rawData, wizardInfo);
        
        //dlg.setVisible(false);
        
        endProgressStatus();

        if (!ready) {
            String str = getErrorMessage();
            if (str.equals("")) {
                String errorMsg = mResource.getString(
                  mPanelName+"_ERRORMSG");
                setErrorMessage(errorMsg);
            } else
                setErrorMessage(str);
        }

        return ready;
    }

    public void callHelp() {
        CMSAdminUtil.help(mHelpIndex);
    }

    protected void init() {
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        setLayout(gb);

/*
        desc = new JTextArea(2, 80);
        desc.setBackground(getBackground());
        desc.setEditable(false);
        desc.setCaretColor(getBackground());
*/
        desc = createTextArea("");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(desc, gbc);

        super.init();
    }

    public void getUpdateInfo(WizardInfo info) {
    }
}
