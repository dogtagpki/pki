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
import java.awt.event.*;
import java.util.*;
import javax.swing.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.certsrv.common.*;
import com.netscape.admin.certsrv.task.*;
import com.netscape.management.client.console.*;
import com.netscape.management.client.util.*;

/**
 * Introduction page for installation wizard.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WIServicesPage extends WizardBasePanel implements IWizardPanel {
    private JRadioButton mCACheckBox;
    private JRadioButton mRACheckBox;
    private JRadioButton mOCSPCheckBox;
    private JRadioButton mKRACheckBox;

    private JRadioButton mTKSCheckBox;
    private JTextArea    mServiceLbl;

    private static final String PANELNAME = "SERVICESWIZARD";
    private static final String HELPINDEX =
      "install-services-configuration-wizard-help";

    private String mClonedSubsystem = null;

    WIServicesPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
        init();
    }

    WIServicesPage(JDialog parent, JFrame adminFrame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = adminFrame;
        init();
    }

    public boolean isLastPage() {
        return false;
    }

    public boolean initializePanel(WizardInfo info) {

        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
		/* bug#54369 - disable RA for netkey */
		mRACheckBox.setEnabled(false);

        mClonedSubsystem = wizardInfo.getCloneSubsystem();


        if(mClonedSubsystem != null)
        {

            mServiceLbl.setText(mResource.getString(PANELNAME +"_LABEL_INSTALL_CLONE_LABEL"));
            if(mClonedSubsystem.equals(ConfigConstants.PR_CA))
            {
                mCACheckBox.setSelected(true);
            }
            else
                mCACheckBox.setEnabled(false);

			/* bug#54369 - disable RA for netkey
            if(mClonedSubsystem.equals(ConfigConstants.PR_RA))
            {
                mRACheckBox.setSelected(true);
            }
            else
                mRACheckBox.setEnabled(false);
			*/

           if(mClonedSubsystem.equals(ConfigConstants.PR_KRA))
           {
                mKRACheckBox.setSelected(true);
            }
            else
                mKRACheckBox.setEnabled(false);

            if(mClonedSubsystem.equals(ConfigConstants.PR_TKS))
           {
                mTKSCheckBox.setSelected(true);
            }
            else
                mTKSCheckBox.setEnabled(false);

           if(mClonedSubsystem.equals(ConfigConstants.PR_OCSP))
           {
                mOCSPCheckBox.setSelected(true);
           }
           else
                mOCSPCheckBox.setEnabled(false);

        }


        Debug.println("WIServicesPage: initializePanel.");
        Debug.println("WIServicesPage: mClonedSubsystem " + mClonedSubsystem);


        if (wizardInfo.isServicesDone())
            return false;

        setBorder(makeTitledBorder(PANELNAME));
        String subsystemList = wizardInfo.getSubsystems();
        if (subsystemList == null || subsystemList.equals("")) {
            if (!mRACheckBox.isSelected() && mClonedSubsystem == null)
                mCACheckBox.setSelected(true);

            return true;
        }



        // get the subsystems from the list
        int start = 0;
        int end;
        do {
            end = subsystemList.indexOf(':', start);
            if( end == -1 ) {
                end = subsystemList.length(); // last string ends at end-of-line
            }
            if( end-start < 1 ) {
                setErrorMessage("INCORRECTRESPONSE");
                return false;
            }
            String sub = subsystemList.substring(start, end);
            if( ConfigConstants.PR_CA.equals(sub) ) {
                mCACheckBox.setSelected(true);
            } else if( ConfigConstants.PR_RA.equals(sub) ) {
                mRACheckBox.setSelected(true);
            } else if( ConfigConstants.PR_KRA.equals(sub) ) {
                mKRACheckBox.setSelected(true);
            } else if( ConfigConstants.PR_TKS.equals(sub) ) {
                mTKSCheckBox.setSelected(true);
            } else if( ConfigConstants.PR_OCSP.equals(sub) ) {
                mOCSPCheckBox.setSelected(true);
            } else {
                setErrorMessage("INCORRECTRESPONSE");
                return false;
            }
            start = end+1;
        } while( start < subsystemList.length() );

        return true;
    }

    public boolean validatePanel() {
        if (mCACheckBox.isSelected() && mRACheckBox.isSelected()) {
            setErrorMessage("NOCOLOCATED");
            return false;
        }

        if (!mCACheckBox.isSelected() && !mRACheckBox.isSelected() &&
           !mOCSPCheckBox.isSelected() && !mKRACheckBox.isSelected() && !mTKSCheckBox.isSelected()) {
            setErrorMessage("NOSERVICESINSTALLED");
            return false;
        }

        return true;
    }

    public boolean concludePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        Hashtable data = new Hashtable();
        String services = "";
        if (mCACheckBox.isSelected()) {
            wizardInfo.setInstalledCA(ConfigConstants.TRUE);
            data.put(ConfigConstants.PR_CA, ConfigConstants.TRUE);
            if (!services.equals(""))
                services = services+":";
            services=services+ConfigConstants.PR_CA;
        } else {
            wizardInfo.setInstalledCA(ConfigConstants.FALSE);
            data.put(ConfigConstants.PR_CA, ConfigConstants.FALSE);
        }

        if (mRACheckBox.isSelected()) {
            wizardInfo.setInstalledRA(ConfigConstants.TRUE);
            data.put(ConfigConstants.PR_RA, ConfigConstants.TRUE);
            if (!services.equals(""))
                services = services+":";
            services=services+ConfigConstants.PR_RA;
        } else {
            wizardInfo.setInstalledRA(ConfigConstants.FALSE);
            data.put(ConfigConstants.PR_RA, ConfigConstants.FALSE);
        }
        if (mKRACheckBox.isSelected()) {
            wizardInfo.setInstalledKRA(ConfigConstants.TRUE);
            data.put(ConfigConstants.PR_KRA, ConfigConstants.TRUE);
            if (!services.equals(""))
                services = services+":";
            services=services+ConfigConstants.PR_KRA;
        } else {
            wizardInfo.setInstalledKRA(ConfigConstants.FALSE);
            data.put(ConfigConstants.PR_KRA, ConfigConstants.FALSE);
        }
        if (mTKSCheckBox.isSelected()) {
            wizardInfo.setInstalledTKS(ConfigConstants.TRUE);
            data.put(ConfigConstants.PR_TKS, ConfigConstants.TRUE);
            if (!services.equals(""))
                services = services+":";
            services=services+ConfigConstants.PR_TKS;
        } else {
            wizardInfo.setInstalledTKS(ConfigConstants.FALSE);
            data.put(ConfigConstants.PR_TKS, ConfigConstants.FALSE);
        }
        if (mOCSPCheckBox.isSelected()) {
            wizardInfo.setInstalledOCSP(ConfigConstants.TRUE);
            data.put(ConfigConstants.PR_OCSP, ConfigConstants.TRUE);
            if (!services.equals(""))
                services = services+":";
            services=services+ConfigConstants.PR_OCSP;
        } else {
            wizardInfo.setInstalledOCSP(ConfigConstants.FALSE);
            data.put(ConfigConstants.PR_OCSP, ConfigConstants.FALSE);
        }

        if (services != null && !services.equals("")) {
            wizardInfo.setSubsystems(services);
        }


        String rawData = ConfigConstants.PR_SUBSYSTEMS+"="+services;
        rawData = rawData+"&"+ConfigConstants.TASKID+"="+TaskId.TASK_SELECT_SUBSYSTEMS;
        rawData = rawData+"&"+ConfigConstants.OPTYPE+"="+OpDef.OP_MODIFY;
        if (wizardInfo.getDBBindDN() != null)
            rawData = rawData+"&"+ConfigConstants.PR_DB_BINDDN+"="+wizardInfo.getDBBindDN();
        if (wizardInfo.getInternalDBPasswd() != null)
            rawData = rawData+"&"+ConfigConstants.PR_DB_PWD+"="+
              wizardInfo.getInternalDBPasswd();

        rawData = rawData+"&"+ConfigConstants.REMOTE_KRA_ENABLED+"="+
          ConfigConstants.FALSE;
        wizardInfo.enableRemoteDRM(ConfigConstants.FALSE);
        startProgressStatus();

        //CMSMessageBox dlg = new CMSMessageBox(mAdminFrame, "CGITASK", "CREATESUB");
        boolean ready = send(rawData, wizardInfo);
        //dlg.setVisible(false);
        endProgressStatus();

        if (!ready) {
            String str = getErrorMessage(wizardInfo);
            if (str.equals("")) {
                String errorMsg = mResource.getString(
                  PANELNAME+"_ERRORMSG");
                setErrorMessage(errorMsg);
            } else
                setErrorMessage(str);
        }

        return ready;
    }

    public void actionPerformed(ActionEvent e) {
        if (e.getSource().equals(mCACheckBox)) {
                    mTKSCheckBox.setSelected(false);
                    mKRACheckBox.setSelected(false);
                    mOCSPCheckBox.setSelected(false);
                    if(mClonedSubsystem != null)
                        mCACheckBox.setSelected(true);

                    mRACheckBox.setSelected(false);
        } else if (e.getSource().equals(mOCSPCheckBox)) {
                    mTKSCheckBox.setSelected(false);
                    mKRACheckBox.setSelected(false);
                    mCACheckBox.setSelected(false);
                    mRACheckBox.setSelected(false);
                    if(mClonedSubsystem != null)
                        mOCSPCheckBox.setSelected(true);
        } else if (e.getSource().equals(mRACheckBox)) {
                    mCACheckBox.setSelected(false);
                    mTKSCheckBox.setSelected(false);
                    mKRACheckBox.setSelected(false);
                    mOCSPCheckBox.setSelected(false);
                    if(mClonedSubsystem != null)
                        mRACheckBox.setSelected(true);
        } else if (e.getSource().equals(mKRACheckBox)) {
                    mTKSCheckBox.setSelected(false);
                    mCACheckBox.setSelected(false);
                    mRACheckBox.setSelected(false);
                    mOCSPCheckBox.setSelected(false);
                    if(mClonedSubsystem != null)
                        mKRACheckBox.setSelected(true);
        }else if (e.getSource().equals(mTKSCheckBox)) {
                    mCACheckBox.setSelected(false);
                    mRACheckBox.setSelected(false);
                    mOCSPCheckBox.setSelected(false);
                    mKRACheckBox.setSelected(false);
                    if(mClonedSubsystem != null)
                        mTKSCheckBox.setSelected(true);
        }

	super.actionPerformed(e);
    }

    public void callHelp() {
        CMSAdminUtil.help(HELPINDEX);
    }

    protected void init() {
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        setLayout(gb);

        mServiceLbl = createTextArea(mResource.getString(
          PANELNAME+"_LABEL_INSTALL_LABEL"));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mServiceLbl, gbc);

        mCACheckBox = makeJRadioButton("CA");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mCACheckBox, gbc);

        mOCSPCheckBox = makeJRadioButton("OCSP");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE, 0,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mOCSPCheckBox, gbc);

        mRACheckBox = makeJRadioButton("RA");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, 0, COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mRACheckBox, gbc);

        mKRACheckBox = makeJRadioButton("KRA");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        //gbc.weighty = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE, COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mKRACheckBox, gbc);

        mTKSCheckBox = makeJRadioButton("TKS");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        //gbc.weighty = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE, COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mTKSCheckBox, gbc);

       JLabel dummy = new JLabel(" ");
       CMSAdminUtil.resetGBC(gbc);
       gbc.anchor = gbc.NORTHWEST;
       gbc.gridwidth = gbc.REMAINDER;
       gbc.gridheight = gbc.REMAINDER;
       gbc.weighty = 1.0;
       add(dummy, gbc);

        super.init();
    }

    public void getUpdateInfo(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        if (mCACheckBox.isSelected())
            wizardInfo.setInstalledCA(ConfigConstants.TRUE);
        else
            wizardInfo.setInstalledCA(ConfigConstants.FALSE);
        if (mRACheckBox.isSelected())
            wizardInfo.setInstalledRA(ConfigConstants.TRUE);
        else
            wizardInfo.setInstalledRA(ConfigConstants.FALSE);
        if (mKRACheckBox.isSelected())
            wizardInfo.setInstalledKRA(ConfigConstants.TRUE);
        else
            wizardInfo.setInstalledKRA(ConfigConstants.FALSE);
        if (mTKSCheckBox.isSelected())
            wizardInfo.setInstalledTKS(ConfigConstants.TRUE);
        else
            wizardInfo.setInstalledTKS(ConfigConstants.FALSE);
        if (mOCSPCheckBox.isSelected())
            wizardInfo.setInstalledOCSP(ConfigConstants.TRUE);
        else
            wizardInfo.setInstalledOCSP(ConfigConstants.FALSE);
    }
}
