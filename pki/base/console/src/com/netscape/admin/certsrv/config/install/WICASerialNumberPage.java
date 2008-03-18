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
import java.math.*;
import javax.swing.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.certsrv.common.*;
import com.netscape.admin.certsrv.task.*;
import com.netscape.management.client.console.*;

/**
 * This panel asks for the starting serial number that the CA issues
 *
 * @author Michelle Zhao
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 * @see com.netscape.admin.certsrv.config.install
 */
class WICASerialNumberPage extends WizardBasePanel implements IWizardPanel {
    private JTextArea mDesc;

    private String mSerialNumber;
    private JTextField mSerialNumberText;
    private JLabel mSerialNumberLabel;

    private String mEndSerialNumber = null;
    private JTextField mEndSerialNumberText;
    private JLabel mEndSerialNumberLabel;
    
    private String mbeginRequestNumber;
    private JTextField mbeginRequestNumberText;
    private JLabel mbeginRequestNumberLabel;
    
    private String mEndRequestNumber = null;
    private JTextField mEndRequestNumberText;
    private JLabel mEndRequestNumberLabel;
    
    private static final String DEFAULT_SERIAL_NUMBER = "1";
    private static final String PANELNAME = "CASERIALNUMBERWIZARD";
    private static final String HELPINDEX =
      "install-ca-serialnumber-wizard-help";

    WICASerialNumberPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
        init();
    }

    WICASerialNumberPage(JDialog parent, JFrame adminFrame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = adminFrame;
        init();
    }

    public boolean isLastPage() {
        return false;
    }

    public boolean initializePanel(WizardInfo info) {
		String serial;
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        setBorder(makeTitledBorder(PANELNAME));
		// If ca's signing cert is not generated, 
		// we allow "back" to modify the panel
        
        if (!wizardInfo.isCAInstalled() || wizardInfo.isMigrationEnable() ||
            wizardInfo.isSelfSignedCACertDone() || wizardInfo.isCACertRequestDone()
            ||wizardInfo.isNumberPageDone())
            return false;

		if (wizardInfo.isCloning())
			mDesc.setText(mResource.getString(PANELNAME+"_TEXT_HEADING_LABEL")
					 + mResource.getString(PANELNAME+"_TEXT_MORE_LABEL"));
		else 
			mDesc.setText(mResource.getString(PANELNAME+"_TEXT_HEADING_LABEL"));


        if ((serial = wizardInfo.getCASerialNumber()) != null)
        	mSerialNumberText.setText(serial);
		else
        	mSerialNumberText.setText(DEFAULT_SERIAL_NUMBER);

        if ((serial = wizardInfo.getRequestNumber()) != null)
        	mbeginRequestNumberText.setText(serial);
		else
        	mbeginRequestNumberText.setText(DEFAULT_SERIAL_NUMBER);
        
        if ((serial = wizardInfo.getCAEndSerialNumber()) != null)
        	mEndSerialNumberText.setText(serial);

        if ((serial = wizardInfo.getEndRequestNumber()) != null)
        	mEndRequestNumberText.setText(serial);
        
        return true; 
    }

    private String hexToDecimal(String hex, boolean isHex)
    {
        //String newHex = hex.substring(2);
        BigInteger bi;
        if(isHex)
         bi = new BigInteger(hex, 16);
        else
            bi = new BigInteger(hex, 10);
        return bi.toString();
    }

    private String DecToHex(String dec)
    {
        BigInteger bi;
        bi = new BigInteger(dec, 10);
        return bi.toString(16);
    }

    private boolean validateNumber(JTextField beginNumberField, JTextField endNumberField,String beginText, String endText,boolean isSerialNumber)
    {
        BigInteger num = null;
        BigInteger endNum = null;
        String serial = null;
        beginText = beginNumberField.getText().trim();
        if (beginText != null && !beginText.equals("")) {
            try {
                if (beginText.startsWith("0x")) {
                  serial = hexToDecimal(beginText.substring(2),true);
                } else {
                  serial = beginText;
                }
                num = new BigInteger(serial);
                if (num.compareTo(new BigInteger("0")) < 0) {
                    setErrorMessage("You must specify a positive value.");
                    return false;
                }
            } catch (NumberFormatException e) {
                setErrorMessage("You must specify a numeric value.");
                return false;
            }
            if(isSerialNumber)
              mSerialNumber = DecToHex(serial); // Hex to the server
            else
              mbeginRequestNumber = serial;
        } else {
            if(isSerialNumber)
              mSerialNumber = "";
            else
              mbeginRequestNumber = "";
        }
        endText = endNumberField.getText().trim();
        if (endText != null && !endText.equals("")) {
            try {
                if (endText.startsWith("0x")) {
                  serial = hexToDecimal(endText.substring(2),true);
                } else {
                  serial = endText;
                }
                endNum = new BigInteger(serial);
                if (endNum.compareTo(new BigInteger("0")) < 0) {
                    setErrorMessage("You must specify a positive value.");
                    return false;
                }
            } catch (NumberFormatException e) {
                setErrorMessage("You must specify a numeric value.");
                return false;
            }
            if(isSerialNumber)
              mEndSerialNumber = DecToHex(serial); // Hex to the Server
            else
              mEndRequestNumber = serial;
        } else {
            if(isSerialNumber)
              mEndSerialNumber = "";
            else
              mEndRequestNumber = "";
        }
        
        if (num != null && endNum != null && num.compareTo(endNum) > 0) {
            setErrorMessage("Ending number must be greater than starting number.");
            return false;
        }
        return true;
    }
    public boolean validatePanel() {

       if(validateNumber(mSerialNumberText,mEndSerialNumberText,mSerialNumber,mEndSerialNumber,true)==false)
            return false;
       if(validateNumber(mbeginRequestNumberText,mEndRequestNumberText,mbeginRequestNumber,mEndRequestNumber,false)==false)
            return false;

        return true;
    }

    public boolean concludePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
		if (mSerialNumber != null && !mSerialNumber.equals("")) 
			wizardInfo.setCASerialNumber(mSerialNumber);
		else {
			wizardInfo.setCASerialNumber(DEFAULT_SERIAL_NUMBER);
			mSerialNumber = DEFAULT_SERIAL_NUMBER;
		}
		if (mbeginRequestNumber != null && !mbeginRequestNumber.equals("")) 
			wizardInfo.setRequestNumber(mbeginRequestNumber);
		else {
			wizardInfo.setRequestNumber(DEFAULT_SERIAL_NUMBER);
			mbeginRequestNumber = DEFAULT_SERIAL_NUMBER;
		}

        String rawData = ConfigConstants.TASKID+"="+TaskId.TASK_SET_CA_SERIAL;
        rawData = rawData+"&"+ConfigConstants.OPTYPE+"="+OpDef.OP_MODIFY;
		if (mSerialNumber != null && !mSerialNumber.equals("")) 
            rawData = rawData+"&"+ConfigConstants.PR_CA_SERIAL_NUMBER+"="+
              mSerialNumber;
		if (mEndSerialNumber != null && !mEndSerialNumber.equals("")) 
            rawData = rawData+"&"+ConfigConstants.PR_CA_ENDSERIAL_NUMBER+"="+
              mEndSerialNumber;
		if (mbeginRequestNumber != null && !mbeginRequestNumber.equals("")) 
            rawData = rawData+"&"+ConfigConstants.PR_REQUEST_NUMBER+"="+
              mbeginRequestNumber;
		if (mEndRequestNumber != null && !mEndSerialNumber.equals("")) 
            rawData = rawData+"&"+ConfigConstants.PR_ENDREQUEST_NUMBER+"="+
              mEndRequestNumber;
        if (wizardInfo.getInternalDBPasswd() != null)
            rawData = rawData+"&"+ConfigConstants.PR_DB_PWD+"="+
              wizardInfo.getInternalDBPasswd();

        rawData = rawData+"&"+ConfigConstants.PR_SERIAL_REQUEST_NUMBER+"="+
          ConfigConstants.TRUE;
        startProgressStatus();

        boolean ready = send(rawData, wizardInfo);
        endProgressStatus();

        if (!ready) {
            String str = getErrorMessage(wizardInfo);
            if (str.equals(""))
                setErrorMessage("Server Error");
            else
                setErrorMessage(str);
        }else {
             wizardInfo.setNumberPageDone(ConfigConstants.TRUE);
        }

        return ready;
    }

    public void callHelp() {
        CMSAdminUtil.help(HELPINDEX);
    }

    protected void init() {
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        setLayout(gb);

        CMSAdminUtil.resetGBC(gbc);
        mDesc = createTextArea(mResource.getString(
            PANELNAME+"_TEXT_HEADING_LABEL"));
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(mDesc, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mSerialNumberLabel = makeJLabel("SERIALNUMBER");
        gbc.anchor = gbc.EAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mSerialNumberLabel, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mSerialNumberText = makeJTextField(30);
        gbc.anchor = gbc.NORTHWEST;
//        gbc.fill = gbc.NONE;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mSerialNumberText, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mEndSerialNumberLabel = makeJLabel("ENDSERIALNUMBER");
        gbc.anchor = gbc.EAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mEndSerialNumberLabel, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mEndSerialNumberText = makeJTextField(30);
        gbc.anchor = gbc.NORTHWEST;
//        gbc.fill = gbc.NONE;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mEndSerialNumberText, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mbeginRequestNumberLabel = makeJLabel("REQUESTNUMBER");
        gbc.anchor = gbc.EAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mbeginRequestNumberLabel, gbc);
        
        CMSAdminUtil.resetGBC(gbc);
        mbeginRequestNumberText = makeJTextField(30);
        gbc.anchor = gbc.NORTHWEST;
//        gbc.fill = gbc.NONE;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mbeginRequestNumberText, gbc);
        
        CMSAdminUtil.resetGBC(gbc);
        mEndRequestNumberLabel = makeJLabel("ENDREQUESTNUMBER");
        gbc.anchor = gbc.EAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mEndRequestNumberLabel, gbc);
        
        CMSAdminUtil.resetGBC(gbc);
        mEndRequestNumberText = makeJTextField(30);
        gbc.anchor = gbc.NORTHWEST;
//        gbc.fill = gbc.NONE;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mEndRequestNumberText, gbc);
        
        /*
        CMSAdminUtil.resetGBC(gbc);
        mSerialNumberLabel = makeJLabel("PWD");
        gbc.anchor = gbc.NORTHEAST;
        gbc.fill = gbc.NONE;
        gbc.insets = new Insets(0, 0, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mSerialNumberLabel, gbc);
        
        CMSAdminUtil.resetGBC(gbc);
        mSerialNumberText = makeJSerialNumberField(30);
        gbc.anchor = gbc.NORTHWEST;
        gbc.fill = gbc.NONE;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(0, COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE);
        add(mSerialNumberText, gbc);
*/
        JLabel dummy = new JLabel(" ");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weighty = 1.0;
        add(dummy, gbc);
    }

    public void getUpdateInfo(WizardInfo info) {
    }
}
