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

import java.io.*;
import java.net.*;
import java.awt.*;
import java.awt.event.*;
import java.util.*;
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.*;
import javax.swing.text.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.certsrv.common.*;
import com.netscape.admin.certsrv.config.*;
import com.netscape.admin.certsrv.task.*;
import com.netscape.management.client.console.*;
import com.netscape.management.client.comm.*;
import com.netscape.management.client.util.*;

/**
 * Setup Single Signon for the installation wizard.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WISingleSignonPage extends WizardBasePanel implements IWizardPanel, CommClient {

    public static final String PW_TAG_INTERNAL_LDAP_DB = "Internal LDAP Database";
    public static final String PW_TAG_INTERNAL_STORAGE_TOKEN = "internal";

    private Color mActiveColor;
	//    private JPasswordField mSingleSignonPassword, mSingleSignonPasswordAgain;
	private JCheckBox mPasswordConf;
    private static final String HELPINDEX = "install-single-signon-wizard-help";
    private static final String PANELNAME = "INSTALLSINGLESIGNON";
    private boolean ca;
    private boolean ra;
    private boolean kra;
    private String mDBPasswd;
    private String capassword, rapassword, krapassword, sslpassword;
    private JComboBox mTokenBox;
    private static final String START_TASK_CGI = "Tasks/Operation/start";
    private static final String PREFIX = "CGITASK";
    private boolean mFinished = false;
    protected String mCmd = null;
    private String mAdminURL = null;
    protected boolean mSuccess = false;
    private String mReply = null;
    protected String mSection = "";
    protected String mErrorMsg = "";
    private ConsoleInfo _consoleInfo = null;
    
    WISingleSignonPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
        init();
    }

    WISingleSignonPage(JDialog parent, JFrame adminFrame) {
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

        String tokenList = wizardInfo.getTokensList();
        StringTokenizer st1 = new StringTokenizer(tokenList, ":");
 
        mTokenBox.removeAllItems();
        while (st1.hasMoreElements()) {
            String t1 = (String)st1.nextElement();
            mTokenBox.addItem(t1);
        }

        mDBPasswd = wizardInfo.getInternalDBPasswd();

        String tokenname = "";
        String password = "";
        if (wizardInfo.isCAInstalled()) {
            tokenname = wizardInfo.getCATokenName();
            password = (String)wizardInfo.get("TOKEN:"+tokenname);
            if (password == null || password.equals("")) {
                capassword = "";
            } else {
                capassword = password;
            }
            ca = true;
        } else {
            capassword = "";
            ca = false;
        }
 
        if (wizardInfo.isRAInstalled()) {
            tokenname = wizardInfo.getRATokenName();
            password = (String)wizardInfo.get("TOKEN:"+tokenname);
            if (password == null || password.equals("")) {
                rapassword = "";
            } else {
                rapassword = password;
            }
            ra = true;
        } else {
            rapassword = "";
            ra = false;
        }

        if (wizardInfo.isKRAInstalled()) {
            tokenname = wizardInfo.getKRATokenName();
            password = (String)wizardInfo.get("TOKEN:"+tokenname);
            if (password == null || password.equals("")) {
                krapassword = "";
            } else {
                krapassword = password;
            }
            kra = true;
        } else {
            krapassword = "";
            kra = false;
        }

        tokenname = wizardInfo.getSSLTokenName();
        password = (String)wizardInfo.get("TOKEN:"+tokenname);
        if (password == null || password.equals("")) {
            sslpassword = "";
        } else {
            sslpassword = password;
        }
        setBorder(makeTitledBorder(PANELNAME));
        return true; 
    }

    public boolean validatePanel() {
        return true;
    }


    /**
     * Copy from CGITask.java
     */
    public boolean run(String cmd) {
        // get the admin URL location first
        String mAdminURL = _consoleInfo.getAdminURL();
        if ( mAdminURL == null ) {
            return false;
        }

        // Allow specifying e.g. "slapd-install" for instance
        String instance = (String)_consoleInfo.get( cmd );
        if (instance == null)
            instance = (String)_consoleInfo.get( "ServerInstance" );
        String fullCmd = mAdminURL + instance + "/" + cmd;

        HttpManager h = new HttpManager();
        // tell the http manager to use UTF8 encoding
        h.setSendUTF8(true);

        try {
            mSuccess = false;
            mFinished = false;

            // _consoleInfo.get("arguments") is a hashtable of key/value pairs
            // to use as the arguments to the CGI
            Hashtable args = (Hashtable)_consoleInfo.get("arguments");
            ByteArrayInputStream data = null;
            if (args != null && !args.isEmpty())
                data = com.netscape.admin.certsrv.task.CGITask.encode(args);
            Debug.println( "Posting " + fullCmd );
            // tell the http manager to notify us immediately of replies
            // if we're using async mode
            int flags = 0;
            if (data == null)
                h.post(new URL(fullCmd), this, null, null, 0, flags);
            else
                h.post(new URL(fullCmd), this, null, data, data.available(),
                    flags);
            awaitSuccess();
            Debug.println( "Command executed: " + fullCmd );
        } catch (Exception e) {
            if (e instanceof java.net.ConnectException) {
                CMSAdminUtil.showMessageDialog(mResource,
                    PREFIX, "SERVERDOWN", CMSAdminUtil.ERROR_MESSAGE);
            }
            Debug.println( "Command " + fullCmd  + " failed: " + e );
        }
        return mSuccess;
    }

    /**
     *  waiting for the http transaction to be finished.
     */
    public synchronized void awaitSuccess() {
        while (!mFinished) {
            try {
                wait();
            } catch (Exception e) { }
        }
    }

    /**
     *  http transaction finished, notify the process
     */
    public synchronized void finish() {
        mFinished = true;
        notifyAll();
    }

    /**
     *  the operation is finished after we receive the http stream
     */
    public void replyHandler(InputStream response, CommRecord cr) {
        try {
            int nBytes = response.available();
            if ( nBytes > 0 ) {
                // the response from the DS CGIs will typically be in
                // UTF8 encoding
                byte[] data = new byte[nBytes];
                nBytes = response.read( data );
                mReply = new String( data, 0, nBytes, "UTF8" );
                Debug.println( "CGITask.replyHandler: Response (" + nBytes +
                    " bytes) = " + mReply );
                int index = 0;
                if ((mReply.indexOf("NMC_") != -1) &&
                    ((index = mReply.indexOf(":")) != -1)) {
                    String sName = mReply.substring(0, index).trim();
                    String sValue = mReply.substring(index+1).trim();
                    if (sName.equalsIgnoreCase("NMC_Status")) {
                        int code = Integer.parseInt(sValue);
                        mSuccess = (code == 0);
                    } else if (sName.equalsIgnoreCase("NMC_ERRINFO")) {
                        mErrorMsg = sValue;                    }
                }
            }
        } catch ( Exception e ) {
            Debug.println( "CGITask.replyHandler: " + e.toString() );
        }
        finish();
    }

    /**
     *  this function will be called if error occurs
     */
    public void errorHandler(Exception error, CommRecord cr) {
        Debug.println("CGITask.errorHandler: " + error );

        // this is a hack. now we dont know how to set the timeout period longer.
        // We always assume everything is fine so that we can proceed to the next
        // config-cert panel.
        mSuccess = true;
        finish();
    }

    /**
     *  pass the username to the admin server
     */
    public String username(Object authObject, CommRecord cr) {
        Debug.println( "username = " +
            (String)_consoleInfo.getAuthenticationDN());
        return _consoleInfo.getAuthenticationDN();
    }

    /**
     *  pass the user password to the admin server
     */
    public String password(Object authObject, CommRecord cr) {
        Debug.println( "password = " +
                       (String)_consoleInfo.get( "AdminUserPassword" ) );
        return (String)_consoleInfo.get( "AdminUserPassword" );
    }
    /**
     * Starts CMS server.
     */
    public boolean startServer(InstallWizardInfo info) {
        _consoleInfo = info.getAdminConsoleInfo();

        Hashtable configParams = new Hashtable();
        configParams.put("serverRoot",_consoleInfo.get("serverRoot"));
        String servid = (String)_consoleInfo.get("servid");
        int index = servid.indexOf("-");
        if (index != -1) {
            servid = servid.substring(index+1);
        }
        configParams.put("instanceID", servid);
		//        configParams.put("password", info.getSingleSignOnPassword());
        _consoleInfo.put( "ServerInstance", "cert-" + servid);
        _consoleInfo.put("arguments", configParams);
        // Debug.println("password "+dialog.getPassword());

        if (_consoleInfo.get("AdminUsername") == null) {
            _consoleInfo.put("AdminUsername", _consoleInfo.getAuthenticationDN()
);
        }
        Debug.println("AdminUsername = " + _consoleInfo.get("AdminUsername"));

        if (_consoleInfo.get("AdminUserPassword") == null) {
            _consoleInfo.put("AdminUserPassword", _consoleInfo.getAuthenticationPassword());
        }
        Debug.println("AdminUserPassword = " + _consoleInfo.get("AdminUserPassword"));
        // call the CGI program
        Debug.println("CMSStart: start() before run task="+START_TASK_CGI);
        boolean status;
        try {
            status = run(START_TASK_CGI);
        } catch (Exception e) {
            Debug.println("Unexpected Error"+e.toString());
            status = false;
        }
        Debug.println("CMSStart: start() after run status="+status);

        return true;
    }

    public boolean concludePanel(WizardInfo info) {
        // Comment out the single signon codes for now.
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        String rawData = ConfigConstants.TASKID+"="+TaskId.TASK_SINGLE_SIGNON;
        rawData = rawData+"&"+ConfigConstants.OPTYPE+"="+OpDef.OP_MODIFY;
        String tags = PW_TAG_INTERNAL_LDAP_DB;
        rawData = rawData+"&"+PW_TAG_INTERNAL_LDAP_DB+"="+mDBPasswd;
        rawData = rawData+"&pwcTokenname="+(String)(mTokenBox.getSelectedItem());

        String tokenname = "";
        if (!capassword.equals("")) {
            tokenname = wizardInfo.getCATokenName();
            rawData = rawData+"&"+tokenname+"="+capassword;
            tags = tags+":"+tokenname;
        }
     
        if (!rapassword.equals("")) {
            tokenname = wizardInfo.getRATokenName();
            rawData = rawData+"&"+tokenname+"="+rapassword;
            tags = tags+":"+tokenname;
        }
     
        if (!krapassword.equals("")) {
            tokenname = wizardInfo.getKRATokenName();
            rawData = rawData+"&"+tokenname+"="+krapassword;
            tags = tags+":"+tokenname;
        }
     
        if (!sslpassword.equals("")) {
            tokenname = wizardInfo.getSSLTokenName();
            rawData = rawData+"&"+tokenname+"="+sslpassword;
            tags = tags+":"+tokenname;
        }
     
	if (mPasswordConf.isSelected()) {
            rawData = rawData+"&"+ConfigConstants.PR_DELETE_PASSWD_CONF+"="+
              ConfigConstants.TRUE;
	} else {
            rawData = rawData+"&"+ConfigConstants.PR_DELETE_PASSWD_CONF+"="+
              ConfigConstants.FALSE;
	}
        rawData = rawData+"&"+ConfigConstants.PR_SINGLE_SIGNON_PW_TAGS+"="+tags;
        //data.put(ConfigConstants.PR_SINGLE_SIGNON, ConfigConstants.FALSE);
            
        startProgressStatus();
        //CMSMessageBox dlg = new CMSMessageBox(mAdminFrame, "CGITASK", "CREATESSON");
        
       // boolean ready = send(rawData, wizardInfo);

       boolean ready = true;
        if (ready) {
            rawData = ConfigConstants.TASKID+"="+TaskId.TASK_MISCELLANEOUS;
/*
            data.put(ConfigConstants.PR_ADMIN_PASSWD, 
              (String)consoleInfo.get(ConfigConstants.PR_ADMIN_PASSWD));
*/
            ready = send(rawData, wizardInfo);
        } else {
            String str = getErrorMessage();
            if (str.equals("")) {
                String errorMsg = mResource.getString(
                  PANELNAME+"_ERRORMSG");
                setErrorMessage(errorMsg);
            } else
                setErrorMessage(str);
            //dlg.setVisible(false);
        
            endProgressStatus();
            return false;
        }

        //startServer(wizardInfo);

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

    public void callHelp() {
        CMSAdminUtil.help(HELPINDEX);
    }

    protected void init() {
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        setLayout(gb);

        JTextArea desc = createTextArea(mResource.getString(
          PANELNAME+"_TEXT_HEADING_LABEL"));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(desc, gbc);

/*
        JPanel panel1 = new JPanel();
        GridBagLayout gb1 = new GridBagLayout();
        panel1.setLayout(gb1);
        //panel1.setBorder(new EtchedBorder());

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE, COMPONENT_SPACE);
        add(panel1, gbc);         
*/

        JTextArea heading = createTextArea(mResource.getString(
          PANELNAME+"_TEXT_HEADING1_LABEL"));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        //gbc.fill = gbc.NONE;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(2*COMPONENT_SPACE, COMPONENT_SPACE, COMPONENT_SPACE, 0);
        add(heading, gbc);

        JLabel tokenLbl = makeJLabel("TOKEN");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHEAST;
        gbc.fill = gbc.NONE;
        //gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE, 4*COMPONENT_SPACE, 0, COMPONENT_SPACE);
        add(tokenLbl, gbc);

        mTokenBox = new JComboBox();
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        //gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, 0, 0);
        add(mTokenBox, gbc);

        JLabel dum = new JLabel(" ");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.fill = gbc.BOTH;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE, 0, 0);
        add(dum, gbc);
 
        JTextArea passwordConfText = createTextArea(mResource.getString(
          PANELNAME+"_TEXT_PASSWDCONF_LABEL"));
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(4*COMPONENT_SPACE,COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(passwordConfText, gbc);

	mPasswordConf = makeJCheckBox("PASSWDCONF"); 
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(COMPONENT_SPACE,2*COMPONENT_SPACE, 0,
          COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
	add(mPasswordConf, gbc);

        JLabel dummy = new JLabel(" ");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.fill = gbc.BOTH;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        add(dummy, gbc);
    }

    public void getUpdateInfo(WizardInfo info) {
    }
}
