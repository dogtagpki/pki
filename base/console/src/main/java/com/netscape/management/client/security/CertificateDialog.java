/** BEGIN COPYRIGHT BLOCK
 * Copyright (C) 2001 Sun Microsystems, Inc.  Used by permission.
 * Copyright (C) 2005 Red Hat, Inc.
 * All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation version
 * 2.1 of the License.
 *                                                                                 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *                                                                                 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 * END COPYRIGHT BLOCK **/
package com.netscape.management.client.security;

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import javax.swing.*;
import java.net.*;
import java.text.MessageFormat;

import com.netscape.management.client.util.*;
import com.netscape.management.client.console.*;
import com.netscape.management.nmclf.*;
import com.netscape.management.client.components.*;

/**
 * Certificate management dialog
 *
 * The dialog allow user to view and manage all server, ca 
 * certificate along with the crl/ckl.  Certificate request 
 * wizard, and install wizard can also be lunched here.
 *
 */
public class CertificateDialog extends AbstractDialog implements SuiConstants {

    //token information
    JComboBox securityDevice;

    ResourceSet resource = new ResourceSet("com.netscape.management.client.security.securityResource");
    String defaultSecurityDevice = resource.getString("CertificateDialog", "defaultSecurityDevice");

    //password for the selected token
    JButton changePwd;

    //certificate list information
    JTabbedPane certTabs;
    ServerCertificatePane serverCertificatePane;
    CACertificatePane caCertificatePane;
    CRLCertificatePane crlCertificatePane;
    
    CertificateList certList = null;
    Vector tokenList = null;
    Hashtable pwdCache = new Hashtable();
    static Hashtable initTokenWarning = new Hashtable();

    //tab pane name
    String trusted, revoked, server;

    //information that need to be passed around
    String _sie;
    ConsoleInfo _consoleInfo;

    boolean _initFail = false;

    CertificateList getCertList(String token) {
        
        try {

            Hashtable args = new Hashtable();
            args.put("formop", "LIST_CERTIFICATE");
            args.put("sie", _sie);
            args.put("tokenname", token);
            for (Enumeration e=pwdCache.keys(); e.hasMoreElements();) {
                Object tokenPwd = e.nextElement();
                args.put(tokenPwd, pwdCache.get(tokenPwd));
            }
                       
            AdmTask admTask = new AdmTask(new URL(_consoleInfo.getAdminURL() +
                                          "admin-serv/tasks/configuration/SecurityOp"),
                                          _consoleInfo.getAuthenticationDN(),
                                          _consoleInfo.getAuthenticationPassword());

            admTask.setArguments(args);

            // respond to password challenge on demand
            if (SecurityUtil.execWithPwdInput(admTask, args, pwdCache) &&
               (!SecurityUtil.showError(admTask))) {        
                CertificateList certList =  new CertificateList(admTask.getResultString().toString());
                if (certList.needInitInternalToken()) { // in case 6.0 security CGI
                    new SetTokenPwdDialog(this, _consoleInfo, _sie, /*isNew=*/true, token).setVisible(true); 
                }
                return certList;
            }
        } catch (Exception e) {
            SecurityUtil.printException("CertificateDialog::getCertList()",e);
        }
        return null;
    }

    void showVisibleCertTab() {
        certTabs.remove(caCertificatePane);
        certTabs.remove(crlCertificatePane);

        //fast hack, this guareentee to work, since
        //tab are first removed then added
        //we will get exception if we attemp to 
        //add twice
        if (securityDevice.getSelectedItem().toString().equals(defaultSecurityDevice)) {
            certTabs.add(caCertificatePane, trusted);
            certTabs.add(crlCertificatePane, revoked);
        }

        SwingUtilities.getRoot(this).validate();
        SwingUtilities.getRoot(this).repaint();    
    }


    /**
     * 
     * Create an instance of certificate management dialog.  
     * Default token "internal (software)" will be used.
     *
     * @param parent the frame that lunches this dialog
     * @param consoleInfo contain admin server connection information
     * @param sie server instance name (ie. admin-serve-HOSTNAME)
     *
     */
    public CertificateDialog(Frame parent, ConsoleInfo consoleInfo, String sie) {
        this(parent, consoleInfo, sie, "");
    }

    private Vector getSecurityDeviceList() {
        Vector securityDeviceList = new Vector();
        try {
            Hashtable args = new Hashtable();
            args.put("formop", "TOKEN_INFO");
            args.put("sie", _sie);

            AdmTask admTask = new AdmTask(new URL(_consoleInfo.getAdminURL() +
                                          "admin-serv/tasks/configuration/SecurityOp"),
                                          _consoleInfo.getAuthenticationDN(),
                                          _consoleInfo.getAuthenticationPassword());

            admTask.setArguments(args);

            admTask.exec();

            if (admTask.getStatus() == 0) {
                Parser response = new Parser(admTask.getResultString().toString());
                Hashtable tokenTable = new Hashtable();

                String typeKeyword;
                while (response.hasMoreElement()) {
                    typeKeyword = response.nextToken();

                    if (typeKeyword.equals("<TOKENINFO>")) {
                        tokenTable = response.getTokenObject(typeKeyword);
                        break;
                    }
                }

                Enumeration tokens = tokenTable.keys();
                while (tokens.hasMoreElements()) {
                    String tokenName = (String)(tokens.nextElement());
                    Hashtable tokenAttrs = (Hashtable)(tokenTable.get(tokenName));
                    TokenInfo tokenInfo = new TokenInfo(tokenName, tokenAttrs);
                    securityDeviceList.addElement(tokenInfo);
                }
            }
            else { // Error occurred
                String admVersion = admTask.getAdminVersion();
                Debug.println("admserv version = " + admVersion);
                // TOKEN_INFO formop was added in 6.01
                if (!"6.0".equals(admVersion)) {
                    SecurityUtil.showError(admTask);
                }
                securityDeviceList.addElement(TokenInfo.createDefaultToken(defaultSecurityDevice));
            }
        } catch (Exception e) {
            SecurityUtil.printException("CertificateDialog::getSecurityDeviceInfo()", e);
            securityDeviceList.addElement(TokenInfo.createDefaultToken(defaultSecurityDevice));
        }

        return securityDeviceList;
    }
    
    final protected void refresh() {
        try {
            setBusyCursor(true);
            
            certList = getCertList(securityDevice.getSelectedItem().toString());
            serverCertificatePane.setCertData(certList.getServerCerts());
            caCertificatePane.setCertData(certList.getCACerts());
            crlCertificatePane.setCertData(certList.getCRLCerts());
        }
        finally {
            setBusyCursor(false);
        }
    }


    /**
     * Called when HELP button is pressed
     */
    protected void helpInvoked() {
        CertificateListPane pane = (CertificateListPane) certTabs.getSelectedComponent();
        pane.helpInvoked();
    }


    /**
     * 
     * Create an instance of certificate management dialog.  
     *
     * @param parent the frame that lunches this dialog
     * @param consoleInfo contain admin server connection information
     * @param sie server instance name (ie. admin-serve-HOSTNAME)
     * @param tokenName view certificate contain in this token, if "" then default token will be used.
     *
     */
    public CertificateDialog(Frame parent, ConsoleInfo consoleInfo, String sie,
                             String tokenName) {
        super(parent, "", true, CLOSE | HELP, HORIZONTAL);

        this._sie = sie;
        this._consoleInfo = consoleInfo;

        if ((tokenName == null) || (tokenName.length()==0)) {
            tokenName =  defaultSecurityDevice;
        }
                
        initialize(tokenName);
        if (_initFail) {
            return;
        }

        getContentPane().setLayout(new GridBagLayout());

        setTitle(resource.getString("CertificateDialog", "title")+" "+sie);

        trusted = resource.getString("CertificateDialog", "trustedTabLabel");
        revoked = resource.getString("CertificateDialog", "revokedTabLabel");
        server  = resource.getString("CertificateDialog", "serverTabLabel");

        ActionListener pwdChangeListener = new ActionListener() {
                public void actionPerformed(ActionEvent event) {
                    if (event.getActionCommand().equals("CHANGE_PASSWORD")) {
                        (new SetTokenPwdDialog(CertificateDialog.this, _consoleInfo, _sie, false, securityDevice.getSelectedItem().toString())).setVisible(true);
                    }
                }
            };

        changePwd = JButtonFactory.create(resource.getString("CertificateDialog", "changePasswordLabel"), pwdChangeListener, "CHANGE_PASSWORD");
        changePwd.setToolTipText(resource.getString("CertificateDialog", "changePassword_tt"));

        JLabel tokenLabel = new JLabel(resource.getString("CertificateDialog", "tokenDialog"));

        securityDevice = new JComboBox(tokenList) ;
        securityDevice.setEditable(false);

        tokenLabel.setLabelFor(securityDevice);

        setSecurityDevice(tokenName);

        //User select a different security device we need to resetup the certificate
        //information
        ActionListener securityDeviceChangeListener = new ActionListener() {
            public void actionPerformed(ActionEvent event) {
                if (event.getActionCommand().equals("CHANGE_SECURITY_DEVICE")) {
                    TokenInfo token = (TokenInfo)securityDevice.getSelectedItem();
                    if (token.needLogin()) {
                        CertificateDialog.this.changePwd.setEnabled(true);
                    }
                    else {
                        CertificateDialog.this.changePwd.setEnabled(false);
                    }

                    CertificateDialog.this.serverCertificatePane.setTokenName(token.toString());
                    CertificateDialog.this.caCertificatePane.setTokenName(token.toString());

                    SwingUtilities.invokeLater(new Runnable() {
                        public void run() {
                            refresh();
                        }
                    });
                }
            }
        };
        //setup lisetner
        securityDevice.setActionCommand("CHANGE_SECURITY_DEVICE");
        securityDevice.addActionListener(securityDeviceChangeListener);

        //add tab
        certTabs = new JTabbedPane(JTabbedPane.TOP);
        serverCertificatePane = new ServerCertificatePane(certList.getServerCerts(), consoleInfo, sie, securityDevice.getSelectedItem().toString(), this);
        caCertificatePane = new CACertificatePane(certList.getCACerts(), consoleInfo, sie, securityDevice.getSelectedItem().toString(), this);
        crlCertificatePane = new CRLCertificatePane(certList.getCRLCerts(), consoleInfo, sie, this);
        certTabs.add(serverCertificatePane, server);

        showVisibleCertTab();

        int y = 0;

        GridBagUtil.constrain(getContentPane(), tokenLabel,
                              0, y, 1, 1,
                              0.0, 0.0,
                              GridBagConstraints.NORTH, GridBagConstraints.NONE,
                              0, 0, COMPONENT_SPACE, COMPONENT_SPACE);

        GridBagUtil.constrain(getContentPane(), securityDevice,
                              1, y, 1, 1,
                              1.0, 0.0,
                              GridBagConstraints.NORTH, GridBagConstraints.HORIZONTAL,
                              0, 0, COMPONENT_SPACE, COMPONENT_SPACE);

        GridBagUtil.constrain(getContentPane(), changePwd,
                              2, y, 1, 1,
                              0.0, 0.0,
                              GridBagConstraints.WEST, GridBagConstraints.NONE,
                              0, 0, COMPONENT_SPACE, 0);

        GridBagUtil.constrain(getContentPane(), certTabs,
                              0, ++y, 3, 1,
                              1.0, 1.0,
                              GridBagConstraints.NORTH, GridBagConstraints.BOTH,
                              0, 0, 0, 0);

        setMinimumSize(200,200);
        pack();

    }

    public void setVisible(boolean visible) {
        if (!_initFail) {
            super.setVisible(visible);
        }
    }

    public void show() {
        if (!_initFail) {
            super.show();
        }
    }

    /**
     * Read token and cert info
     */
    void initialize(String token) {

        tokenList = getSecurityDeviceList();
        if (!initSecurityDevice(tokenList)) {
            _initFail = true;
            return;
        }
        if ((certList = getCertList(token)) == null) {
            certList = new CertificateList("");
            _initFail = true;
        }
    }

    /**
     * Selects the device in the security device combo box
     */
    void setSecurityDevice(String device) {
        ComboBoxModel model = securityDevice.getModel();
        Object token = null;
        for (int i=0; i < model.getSize(); i++) {
            Object item = model.getElementAt(i);
            if (device.equals(item.toString())) {
                token = item;
                break;
             }
        }
        if (token != null) {
            model.setSelectedItem(token);
        }
    }

    /**
     * Returns true if token initialization was successfully completed
     */
    boolean initSecurityDevice(Vector tokens) {
        for (int i=(tokens.size()-1); i>=0; i--) {
            TokenInfo token = (TokenInfo)tokens.elementAt(i);

            if (token.isInternal() && token.getName().indexOf("Generic Crypto Services") >= 0) {
                // remove Intrnal Generic Crypto Services token from the list
                tokens.removeElement(token);
                continue;
            }

            if (token.needLogin() && token.needInit()) {

                if (token.isHardware()) {
                    // External hardware tokens must be initialized using the
                    // particular vendor tools. The token is not usable, skip it.
                    tokens.removeElement(token);

                    // Notify user but not more then once
                    String id = token.getModule() + ":" + token.getName();
                    if (initTokenWarning.get(id) == null) {
                        initTokenWarning.put(id, new Object());
                        showInitWarningMsg(token.getName(), token.getModule());
                    }
                    continue;
                }

                SetTokenPwdDialog dialog = 
                    new SetTokenPwdDialog(this, _consoleInfo, _sie, true, token.getName());
                dialog.setVisible(true);
                if (dialog.isCancel()) {
                    return false;
                }
            }
        }
        return true;
    }

    void showInitWarningMsg(String token, String module) {
        String title = resource.getString("HardwareTokenInit", "title");
        String msg = resource.getString("HardwareTokenInit", "message");
        String detail = resource.getString("HardwareTokenInit", "detail");
        detail = MessageFormat.format(detail, new Object[] {token, module});        
        ErrorDialog dialog = new ErrorDialog(this, title, msg, null, detail,
            ErrorDialog.OK, ErrorDialog.OK);
        dialog.setIcon(ErrorDialog.WARNING_ICON);
        dialog.setVisible(true);
    }
}

/**
 * TokenInfo stores token information
 */
class TokenInfo {
    private String _name;
    private String _module;
    // token flags
    private boolean _isInternal, _isReadOnly, _isHardware, _isFriendly;
    private boolean _needLogin, _needUserInit;
        
    private TokenInfo() {}

    public TokenInfo(String name, Hashtable attrs) {
        _name = name;
        initAttrs(attrs);
    }

    void initAttrs(Hashtable tokenAttrs) {
        Enumeration attrs = tokenAttrs.keys();
        while (attrs.hasMoreElements()) {
        
            String attrName = attrs.nextElement().toString();
            String attrValue = tokenAttrs.get(attrName).toString();
                        
            if ("MODULE".equalsIgnoreCase(attrName)) {
                _module = attrValue;
            }
            else if ("INTERNAL".equalsIgnoreCase(attrName)) {
                _isInternal = "TRUE".equalsIgnoreCase(attrValue);
            }
            else if ("HARDWARE".equalsIgnoreCase(attrName)) {
                _isHardware = "TRUE".equalsIgnoreCase(attrValue);
            }
            else if ("READONLY".equalsIgnoreCase(attrName)) {
                _isReadOnly = "TRUE".equalsIgnoreCase(attrValue);
            }
            else if ("NEED_LOGIN".equalsIgnoreCase(attrName)) {
                _needLogin = "TRUE".equalsIgnoreCase(attrValue);
            }
            else if ("FRIENDLY".equalsIgnoreCase(attrName)) {
                _isFriendly = "TRUE".equalsIgnoreCase(attrValue);
            }
            else if ("NEED_USER_INIT".equalsIgnoreCase(attrName)) {
                _needUserInit = "TRUE".equalsIgnoreCase(attrValue);
            }
            else {
                Debug.println("TokenInfo.initAttrs: ERROR, unexpected attr name " + attrName);
            }
        }
    }

    String getName() {
        return _name;
    }

    String getModule() {
        return _module;
    }

    boolean isInternal() {
        return _isInternal;
    }

    boolean isHardware() {
        return _isHardware;
    }

    boolean isReadOnly() {
        return _isReadOnly;
    }

    /**
     * Returns true if this is a password protected token (needLogin()==true)
     * and it has not yet been initialized with a password or pin (a call to
     * NSS PK11_InitPin() is required before token can be accessed).
     * If needLogin is false, needInit can be ignored.
     */
    boolean needInit() {
        return _needUserInit;
    }

    /**
     * A password protected token. If false, needInit and isFriendly should be
     * ignored.
     */
    boolean needLogin() {
        return _needLogin;
    }

    /**
     * In PK11, "friendly" means that login is NOT required for reading certs
     * from a password protected token (needLogin()==true). If needLogin is
     * false, isFriendly should be ignored. 
     */
    boolean isFriendly() {
        return _isFriendly;
    }

    static TokenInfo createDefaultToken(String name) {
        TokenInfo token = new TokenInfo();
        token._name = name;
        token._module = "";
        token._isInternal = token._isFriendly = token._needLogin = true;
        return token;
    }

    String toDebugString() {
        StringBuffer sb = new StringBuffer(_name + ":");
        sb.append(" module=\"" + _module + "\" flags=");
        if (_isInternal) {
            sb.append(" Internal");
        }
        if (_isReadOnly) {
            sb.append(" ReadOnly");
        }
        if (_isHardware) {
            sb.append("Hardware");
        }
        if (_needLogin) {
            sb.append(" NeedLogin");
        }
        if (_isFriendly) {
            sb.append(" Friendly");
        }
        if (_needUserInit) {
            sb.append(" NeedUserInit");
        }
        return sb.toString();
    }
        
    /**
     * toString() MUST return only the token name, as TokenInfo object is stored
     * directly in the ComboBoxModel as an element of a Vector.
     */
    public String toString() {
        return _name;
    }        
}
