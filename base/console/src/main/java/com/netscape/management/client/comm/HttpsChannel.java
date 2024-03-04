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
package com.netscape.management.client.comm;

import java.net.*;
import java.util.*;
import java.io.*;

import com.netscape.management.client.util.Debug;
import com.netscape.management.client.util.ResourceSet;
import com.netscape.management.client.util.UtilConsoleGlobals;
import com.netscape.management.client.util.AbstractDialog;
import com.netscape.management.client.util.GridBagUtil;
import com.netscape.management.client.util.RemoteImage;
import com.netscape.management.client.security.PromptForTrustDialog;
import com.netscape.management.nmclf.SuiPasswordField;
import com.netscape.management.client.preferences.Preferences;

import org.mozilla.jss.ssl.SSLSocket;
import org.mozilla.jss.ssl.SSLCertificateApprovalCallback;
import org.mozilla.jss.ssl.SSLClientCertificateSelectionCallback;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.util.PasswordCallback;
import org.mozilla.jss.util.PasswordCallbackInfo;
import org.mozilla.jss.util.Password;
import org.mozilla.jss.crypto.InternalCertificate;

import javax.swing.JFrame;
import javax.swing.SwingUtilities;

import javax.swing.JLabel;
import javax.swing.JComboBox;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Container;

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * The HttpsChannel is an implementation of the CommChannel interface
 * for HTTP protocol connections, over an SSL socket.
 *
 */
public class HttpsChannel extends HttpChannel implements
                               SSLCertificateApprovalCallback,
                               SSLClientCertificateSelectionCallback,
                               PasswordCallback{


    protected SSLSocket socket = null;

    static CryptoManager cryptoManager;
    static HttpsChannel.GetPasswordDialog getPasswordDialog = null;
    static HttpsChannel.SelectCertDialog selectCertDialog = null;
    static CertificateFactory cf;
    static ResourceSet resource;
    private JFrame _frame; 

    final static int MAX_PASSWORD_PROMPT = 10;
    int nthPrompt = 0;

    static {
        try {
            resource = new ResourceSet("com.netscape.management.client.comm.HttpsChannel");

            /* WARNING by Shih Ming! Must obtain all the sun provider stuff before 
               executing any jss code.  JSS is also a provider (broken one)
               which will clobber with the default one provided by sun.
            
               UtilConsoleGlobals.initJSS() takes care of that and records
               the SUN X509 CertificateFactory before the JSS CryptoManager
               is initialized.
            */
            UtilConsoleGlobals.initJSS();
            cf = UtilConsoleGlobals.getX509CertificateFactory();
            cryptoManager = CryptoManager.getInstance();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String i18n(String id)
    {
        return resource.getString("HttpsChannel", id);
    }

    private static String i18n(String id, String arg)
    {
        return resource.getString("HttpsChannel", id, arg);
    }

    protected HttpsChannel(Object _tid, String _name,
            HttpManager _manager) {
        super(_tid, _name, _manager);
    }

    /**
      * On Windows create a hidden frame on demand to override the Java Cup icon 
      */
    private JFrame getFrame() {
        if (UtilConsoleGlobals.getActivatedFrame() != null) {
            return UtilConsoleGlobals.getActivatedFrame();
        }

        boolean isWin = System.getProperty("os.name").startsWith("Windows");
	
        if (isWin && _frame == null) {
            _frame = new JFrame();
            // Set the icon image so that login dialog will inherit it
            _frame.setIconImage( new RemoteImage("com/netscape/management/client/theme/images/logo16.gif").getImage());
        }
        return _frame;
    }

    private static PromptForTrustDialog promptForTrustDialog = null;
    public boolean approve(org.mozilla.jss.crypto.X509Certificate serverCert,
                           ValidityStatus status) {

        boolean promptForTrust = true;
        boolean accepted = true;

        //if server auth is not enabled
        if (!(UtilConsoleGlobals.isServerAuthEnabled())) {
            return accepted;
        }


        Enumeration errors = status.getReasons();
        //if there are more then 1 error we need to propmt user for trust
        promptForTrust = errors.hasMoreElements();

        Debug.println("This certificate is "+(promptForTrust?"not ":"")+"a trusted server Certificate");


        //the x509certificate pass in by jss is lacking some
        //api.  so I am getting the encoding then
        //use the default security provider provided by sun
        //to decode certificate.
        //due to the fact that current JSS(version2.1) will clobber
        //the way jdk loads the default sun security provider I am
        //using the workaround for now.  Which is to load the sun
        //provider before jss is loaded.  (see static section above)
        X509Certificate x509Cert = null;
        try {
            ByteArrayInputStream bais = new ByteArrayInputStream(serverCert.getEncoded());

            while (bais.available() > 0) {
                x509Cert = (X509Certificate)(cf.generateCertificate(bais));
                Debug.println(x509Cert.toString());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        if (promptForTrustDialog==null) {
            //create prompt for trust dialog
            if (SwingUtilities.isEventDispatchThread()) {
                promptForTrustDialog = new
                    PromptForTrustDialog(getFrame(), x509Cert, status);
            }
            else {
                try {
                    final X509Certificate x509Cert_f = x509Cert;
                    final ValidityStatus status_f = status;
                    SwingUtilities.invokeAndWait( new Runnable() {
                        public void run () {
                            promptForTrustDialog = new
                                PromptForTrustDialog(getFrame(), x509Cert_f, status_f);
                        } 
                   });
                }catch (Exception e) {
                    Debug.println("HttpsChannel: open PromptForTrustDialog " + e);
                }
           }

        } else {
            //already exist just need to pass in the
            // verification cert
            promptForTrustDialog.setCertificateInfo(x509Cert, status);
        }

        //prompt for trust
        if (promptForTrust) {

            showDialog(promptForTrustDialog);

            accepted = promptForTrustDialog.isCertAccepted();

            if (accepted) {
                //user want to save this certificate not just this session
                //so we have to store the cert as perm cert.
                if (!(promptForTrustDialog.isAcceptedForOneSession())) {
                    try {
                        Debug.println("install cert");
                        String nickname = serverCert.getNickname();
                        //serverCert.setSSLTrust(org.mozilla.jss.crypto.InternalCertificate.TRUSTED_PEER);
                        Debug.println("nickname: "+nickname);
                        Debug.println("dn:       "+serverCert.getSubjectDN().toString());
                        InternalCertificate internalCert = cryptoManager.importCertToPerm(serverCert, (nickname==null)?serverCert.getSubjectDN().toString():nickname);
                        internalCert.setSSLTrust(org.mozilla.jss.crypto.InternalCertificate.TRUSTED_PEER | org.mozilla.jss.crypto.InternalCertificate.VALID_PEER);
                    }catch (Exception e) {
                        //unable to save cert
                        //e.printStackTrace();
                        if (Debug.getTrace()) {
                            e.printStackTrace();
                        }
                    }
                }
            }

            Debug.println("ACCEPTED:"+accepted);
        }

        return accepted;
    }


    class GetPasswordDialog extends AbstractDialog {

        JLabel enterPwdLabel = new JLabel();
        SuiPasswordField pwd;
        public GetPasswordDialog(JFrame parent) {
            super(parent, i18n("getPwdDialogTitle"), true, OK|CANCEL);

            Container p = getContentPane();
            p.setLayout(new GridBagLayout());
            
            int y = 0;
            GridBagUtil.constrain(p, enterPwdLabel,
                                    0, y, 1, 1,
                                    1.0, 0.0,
                                    GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                                    0, 0, 0, 0);

            pwd = new SuiPasswordField();
            setFocusComponent(pwd);
            GridBagUtil.constrain(p, pwd,
                                    0, ++y, 1, 1,
                                    1.0, 0.0,
                                    GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                                    0, 0, 0, 0);

            pack();
        }

        public void setVisible(boolean visible) {
            if (visible) {
                pack();
            }
            super.setVisible(visible);
        }

        public void setPasswordInfo(PasswordCallbackInfo info, boolean getPwdAgain) {
            if (getPwdAgain) {
                enterPwdLabel.setText(i18n("enterPwdAgainLabel", info.getName()));
            } else {
                enterPwdLabel.setText(i18n("enterPwdLabel", info.getName()));
            }
            Debug.println(info.getName());
        }

        public Password getPassword() {
            Password jssPwd = new Password(pwd.getText().toCharArray());
            return jssPwd;
        }
    }

    class SelectCertDialog extends AbstractDialog {

        JComboBox certList = new JComboBox();
        public SelectCertDialog(JFrame frame) {
            super(frame, i18n("selectCertDialogTitle"), true, OK|CANCEL);

            Container p = getContentPane();
            p.setLayout(new GridBagLayout());

            int y = 0;
            GridBagUtil.constrain(p, new JLabel(i18n("selectCertLabel")),
                                    0, y, 1, 1,
                                    1.0, 0.0,
                                    GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                                    0, 0, 0, 0);

            GridBagUtil.constrain(p, certList,
                                    0, ++y, 1, 1,
                                    1.0, 0.0,
                                    GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
                                    0, 0, 0, 0);

            setFocusComponent(certList);
            pack();

        }
        
        public void show() {
            java.awt.Dimension d = getPreferredSize();
            int minWidth = 320; // to look better
            if (d.getWidth() < minWidth) {
                d.setSize(minWidth, d.getHeight());
                setMinimumSize(d);
            }
            super.show();
        }
            

        public void setCertList(Vector nicknames) {
            certList.removeAllItems();
            Enumeration nicks_enum = nicknames.elements();
            while (nicks_enum.hasMoreElements()) {
                certList.addItem(nicks_enum.nextElement());
            }
            if (certList.getItemCount() > 0) {
                certList.setSelectedIndex(0);
            }
        }

        public String getSelectedCert() {
            if (certList.getSelectedItem() != null) {
                return certList.getSelectedItem().toString();
            }
            else {
                return "";
            }
        }

        
    }

    //used for client auth to select a certificate
    public String select(Vector nicknames) {

        if (selectCertDialog == null) {
            selectCertDialog = new HttpsChannel.SelectCertDialog(getFrame());
        }

        Debug.println("HttpsChannel::select(...) - SELECT CERTIFICATE");
        selectCertDialog.setCertList(nicknames);
        showDialog(selectCertDialog);
        return (selectCertDialog.isCancel()?"":selectCertDialog.getSelectedCert());
    }

    //prompt for password
    public Password getPasswordFirstAttempt(PasswordCallbackInfo info)
        throws PasswordCallback.GiveUpException {

        nthPrompt++;

        if (getPasswordDialog == null) {
            getPasswordDialog = new HttpsChannel.GetPasswordDialog(getFrame());
        }

        Debug.println("HttpsChannel::getPasswordFirstAttempt(...) - PROMPT FOR PASSWORD");

        getPasswordDialog.setPasswordInfo(info, false);
        showDialog(getPasswordDialog);

        if (getPasswordDialog.isCancel()) {
            throw new PasswordCallback.GiveUpException();
        }

        return getPasswordDialog.getPassword();
    }


    public Password getPasswordAgain(PasswordCallbackInfo info)
        throws PasswordCallback.GiveUpException {

        nthPrompt++;

        Debug.println("HttpsChannel::getPasswordAgainAttempt(...) - PROMPT FOR PASSWORD");

        getPasswordDialog.setPasswordInfo(info, true);
        showDialog(getPasswordDialog);

        if (nthPrompt > MAX_PASSWORD_PROMPT) {
            throw new PasswordCallback.GiveUpException();
        }

        if (getPasswordDialog.isCancel()) {
            throw new PasswordCallback.GiveUpException();
        }

        return getPasswordDialog.getPassword();
    }

    private int getSSLVersionRangeEnum (String rangeString) {
        if (rangeString == null)
            return -1;
        if (rangeString.equalsIgnoreCase("ssl3"))
            return org.mozilla.jss.ssl.SSLVersionRange.ssl3;
        else if (rangeString.equalsIgnoreCase("tls1.0"))
            return org.mozilla.jss.ssl.SSLVersionRange.tls1_0;
        else if (rangeString.equalsIgnoreCase("tls1.1"))
            return org.mozilla.jss.ssl.SSLVersionRange.tls1_1;
        else if (rangeString.equalsIgnoreCase("tls1.2"))
            return org.mozilla.jss.ssl.SSLVersionRange.tls1_2;

        return -1;
    }

    public void open(Preferences pref) throws IOException {
        cryptoManager.setPasswordCallback(this);
        try {
            nthPrompt = 0;

            // Set our defaults
            int min = org.mozilla.jss.ssl.SSLVersionRange.tls1_0;
            int max = org.mozilla.jss.ssl.SSLVersionRange.tls1_2;

            Debug.println("CREATE JSS SSLSocket");

            if(pref != null){
                // Check if min/max have been a preference
                int version;

                if ((version = getSSLVersionRangeEnum(pref.getString("sslVersionMin"))) != -1 ){
                    min = version;
                }
                if ((version = getSSLVersionRangeEnum(pref.getString("sslVersionMax"))) != -1){
                    max = version;
                }
            }

            org.mozilla.jss.ssl.SSLVersionRange range =
                new org.mozilla.jss.ssl.SSLVersionRange(min, max);

            SSLSocket.setSSLVersionRangeDefault(org.mozilla.jss.ssl.SSLProtocolVariant.STREAM, range);

            socket = new SSLSocket(InetAddress.getByName(getHost()),
                                   getPort(), null, 0, true, this,
                                   this);

            socket.forceHandshake();

            super.socket = socket;
        } catch (IOException e) {
            Debug.println("Unable to create ssl socket");
            if (Debug.getTrace()) {
                e.printStackTrace();
            }
            throw e;
        }

        bos = new BufferedOutputStream(socket.getOutputStream(),
                defaultBufferLength);
        bis = new BufferedInputStream(socket.getInputStream(),
                defaultBufferLength);


        Debug.println(name + " open> Ready");

        thread = new Thread(this, tid.toString());
        thread.start();
    }

    public void close() throws IOException {
        dead = true;

        Debug.println(name + " close i/o stream");

        bos.close();
        bis.close();

        Debug.println(name + " close socket");

        //socket.close(true);
        socket.close();
        socket = null;

        Debug.println(name + " close> Closed");
    }

    // Show dialog on the EventDispatchThread
    private static void showDialog(final java.awt.Component d) {
        if (SwingUtilities.isEventDispatchThread()) {
            d.setVisible(true);
        }
        else {
            try {
                SwingUtilities.invokeAndWait( new Runnable () {
                    public void run() {
                      d.setVisible(true);
                    }
                });
            }
            catch (Exception e) {
                Debug.println("HttpsChannel::showDialog  " + e);
            }
        }
    }
}

