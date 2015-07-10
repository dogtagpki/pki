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
package com.netscape.admin.certsrv.connection;

import java.util.*;
import java.net.*;
import java.io.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import com.netscape.admin.certsrv.*;
import com.netscape.certsrv.common.*;
import com.netscape.management.client.util.Debug;
import com.netscape.management.client.util.*;
import org.mozilla.jss.ssl.*;
import org.mozilla.jss.*;
import org.mozilla.jss.util.*;
import org.mozilla.jss.crypto.*;
import org.mozilla.jss.pkcs11.*;
import javax.swing.*;
import java.awt.*;

import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * JSSConnection deals with establishing a connection to
 * a server, sending requests and reading responses.
 *
 * XXX - Performance optimizations if any, persistent connection
 * support, server auth verification and  client authentication
 * support to be added. NEED TO COME BACK AND CLEAN UP - coding
 * standard.
 *
 * @author Jack Pan-Chen
 * @author kanda
 * @author Christine Ho
 * @version $Revision$, $Date$
 */
public class JSSConnection implements IConnection, SSLCertificateApprovalCallback,
  SSLClientCertificateSelectionCallback {

    /*==========================================================
     * variables
     *==========================================================*/

    /* static variables */
    static CryptoManager cryptoManager;
    static CertificateFactory cf;
    static SelectCertDialog selectCertDialog = null;
    static PromptForTrustDialog promptForTrustDialog = null;

    /* private valiable */
    private InputStream httpIn;
    private OutputStream httpOut;
    private byte[] body;
    private int bodyLen;
    private String header;
    private int available;
    private int totalRead;
    private boolean endOfHeader = false;

    private static int HTTP_OK_RESPONSE = 200;
    private static final String PANELNAME = "SSLCLIENT";
    private boolean abort = false;;
    private boolean mClientAuth = false;
    private boolean mCertAccepted = true;
    private boolean mClientCertFound = true;
    private boolean mServerCertImported = true;
    private boolean mTokenPasswordInit = true;
    private boolean mTokenPasswdSame = true;

    protected SSLSocket s = null;

    /*==========================================================
    * constructors
    *==========================================================*/
    public JSSConnection(String host, int port)
        throws IOException, UnknownHostException {

        UtilConsoleGlobals.initJSS();
        cf = UtilConsoleGlobals.getX509CertificateFactory();
        try {
            cryptoManager = CryptoManager.getInstance();
        } catch (Exception e) {
        }

        org.mozilla.jss.ssl.SSLSocket.SSLVersionRange stream_range =
            new org.mozilla.jss.ssl.SSLSocket.SSLVersionRange(
                org.mozilla.jss.ssl.SSLSocket.SSLVersionRange.tls1_0,
                org.mozilla.jss.ssl.SSLSocket.SSLVersionRange.tls1_2);

        SSLSocket.setSSLVersionRangeDefault(
            org.mozilla.jss.ssl.SSLSocket.SSLProtocolVariant.STREAM,
            stream_range);

        org.mozilla.jss.ssl.SSLSocket.SSLVersionRange datagram_range =
            new org.mozilla.jss.ssl.SSLSocket.SSLVersionRange(
                org.mozilla.jss.ssl.SSLSocket.SSLVersionRange.tls1_1,
                org.mozilla.jss.ssl.SSLSocket.SSLVersionRange.tls1_2);

        SSLSocket.setSSLVersionRangeDefault(
            org.mozilla.jss.ssl.SSLSocket.SSLProtocolVariant.DATA_GRAM,
            datagram_range);

        CryptoUtil.setClientCiphers();

        s = new SSLSocket(host, port, null, 0, this, this);

        // Initialze Http Input and Output Streams
        httpIn = s.getInputStream();
        httpOut = s.getOutputStream();
        cryptoManager.setPasswordCallback(new pwcb());
        Debug.println("JSSConnection Debug: end of JSSConnection constructor");
    }

    public boolean approve(org.mozilla.jss.crypto.X509Certificate serverCert,
       ValidityStatus status)
    {
        if (!mCertAccepted)
            return false;

        boolean promptForTrust = true;

        //if server auth is not enabled
        if (!(UtilConsoleGlobals.isServerAuthEnabled())) {
            return mCertAccepted;
        }

        Enumeration errors = status.getReasons();
        //if there are more then 1 error we need to propmt user for trust
        promptForTrust = errors.hasMoreElements();

	    /* if trusted already */
	    if (!promptForTrust)
		    return mCertAccepted;

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

	    //bring up the trust dialog
	    promptForTrustDialog = new PromptForTrustDialog(getFrame(), x509Cert, status);
	    promptForTrustDialog.setVisible(true);
	    mCertAccepted = promptForTrustDialog.isCertAccepted();
	    if (mCertAccepted) {
            //user want to save this certificate not just this session
            //so we have to store the cert as perm cert.
		    if (!(promptForTrustDialog.isAcceptedForOneSession())) {
			    try {
			        String nickname = serverCert.getNickname();

                    CryptoToken internalToken =
                      cryptoManager.getInternalKeyStorageToken();

                    if (!internalToken.passwordIsInitialized()) {
                        InitPasswordDialog initPasswordDialog =
                          new InitPasswordDialog(internalToken);
                        initPasswordDialog.setVisible(true);
                        if (initPasswordDialog.isCancel()) {
                            mTokenPasswordInit = false;
                            return false;
                        }
                        if (!initPasswordDialog.isPwdSame()) {
                            mTokenPasswdSame = false;
                            mTokenPasswordInit = false;
                            return false;
                        }
                        if (!initPasswordDialog.isTokenInit()) {
                            mTokenPasswordInit = false;
                            return false;
                        }
                    }

                    if (!internalToken.isLoggedIn()) {
                        internalToken.login(new pwcb());
                    }
                    if (abort) {
                        mServerCertImported = false;
                        mCertAccepted = false;
                        return false;
                    }
			        InternalCertificate internalCert =
                      cryptoManager.importCertToPerm(serverCert,
                      (nickname==null)?serverCert.getSubjectDN().toString():nickname);
			        internalCert.setSSLTrust(
                      org.mozilla.jss.crypto.InternalCertificate.TRUSTED_PEER |
                      org.mozilla.jss.crypto.InternalCertificate.VALID_PEER);
			    } catch (Exception e) {
                    mServerCertImported = false;
                    mCertAccepted = false;
                    if (Debug.getTrace()) {
                        e.printStackTrace();
                    }
                    return false;
                }
		    }
	    }

        return mCertAccepted;
    }

    public boolean isSamePwd() {
        return mTokenPasswdSame;
    }

    public boolean isTokenPasswordInit() {
        return mTokenPasswordInit;
    }

    public boolean hasClientCert() {
        return mClientCertFound;
    }

    public boolean isClientAuth() {
        return mClientAuth;
    }

    public boolean isCertAccepted() {
        return mCertAccepted;
    }

    public boolean isAbortAction() {
        return abort;
    }

    public boolean isServerCertImported() {
        return mServerCertImported;
    }

    public String select(Vector nicknames)
    {
        selectCertDialog = null;
        mClientAuth = true;
        if (nicknames == null || nicknames.size() == 0) {
            mClientCertFound = false;
            return "";
        }

        selectCertDialog = new JSSConnection.SelectCertDialog();

        Debug.println("JSSConnection::select(...) - SELECT CERTIFICATE");
        selectCertDialog.setCertList(nicknames);
        selectCertDialog.setVisible(true);
        return (selectCertDialog.isCancel()?"":selectCertDialog.getSelectedCert());
    }

    public class pwcb implements PasswordCallback {
        private int nthPrompt = 0;
        private static final int MAX_PASSWORD_PROMPT = 20;
        GetPasswordDialog getPasswordDialog = null;

        public Password getPasswordFirstAttempt(PasswordCallbackInfo info)
            throws PasswordCallback.GiveUpException {

            if (abort)
                throw new PasswordCallback.GiveUpException();

            nthPrompt++;

            if (getPasswordDialog == null)
                getPasswordDialog = new GetPasswordDialog();

            getPasswordDialog.setPasswordInfo(info, false);
            getPasswordDialog.setVisible(true);

            if (getPasswordDialog.isCancel()) {
                nthPrompt = 0;
                abort = true;
                throw new PasswordCallback.GiveUpException();
            }

            return getPasswordDialog.getPassword();
        }

        public Password getPasswordAgain(PasswordCallbackInfo info)
          throws GiveUpException
        {

            if (abort)
                throw new PasswordCallback.GiveUpException();
            nthPrompt++;
            if (nthPrompt > MAX_PASSWORD_PROMPT || getPasswordDialog.isCancel()) {
                nthPrompt = 0;
                abort = true;
                throw new PasswordCallback.GiveUpException();
            }

            getPasswordDialog.setPasswordInfo(info, true);
            getPasswordDialog.setVisible(true);

            return getPasswordDialog.getPassword();
        }
    }

    /*==========================================================
	 * public methods
     *==========================================================*/

    /**
     * Send request to the server using this connection
     *
     * @param req request object
     * @return status 1-success, 0- failed
     * @excpetion IOExcpetion
     */
	public int sendRequest(String req)
	    throws IOException {

		int stat = 1;
		if (req == null)
		{
			//System.out.println("Request is null");
			return 0;
	  	}
		endOfHeader = false;

		PrintStream ps = new PrintStream(httpOut);
		ps.println(req);
		ps.println();
		ps.flush();
		try
		{
			Thread.sleep(100);
		}
		catch (Exception e) {
            Debug.println("JSSConnection Debug: in sendRequest:"+e.toString());
            System.out.println("sleeping "+e.toString());
        }
		//System.out.println("Request Sent - bytes:" + httpOut.getTotal());

		// Init the Reply stream
		totalRead = 0;
		header = null;
		initReadResponse();
		return stat;
	}

    /**
     * Retrieve the input stream
     */
	public InputStream getInputStream()
	    throws IOException {

		return s.getInputStream();
	}

	/**
	 * Read
	 */
	public int read(byte[] buf)
	    throws IOException {

		return httpIn.read(buf, 0, buf.length);
	}

    /**
     * Get Header
     */
	public String getHeader() {
		if (header == null)
			return "No Header Read";
		else
			return header;
	}

    /**
     * Get response
     */
	public byte[] getResponse() {
		if (totalRead == 0)
			return null;
		else {
			byte[] buf = new byte[bodyLen];
			System.arraycopy(body, 0, buf, 0, bodyLen);
			return buf;
		}
	}

    /**
     * get available
     */
	public int available()
	    throws IOException {

		return httpIn.available();
	}

    /**
     * Disconnect this connection
     */
	public void disconnect() {
	    try {
		    s.close();
	    } catch (Exception e) {
	        //ignor ?
	    }
	}

    /**
     * Set time out
     */
    public void setSoTimeout(int timeout) throws SocketException {
        //System.out.println("JSSConnection: setSoTimeout() - "+timeout);
        s.setSoTimeout(timeout);
    }

    /*==========================================================
	 * private methods
     *==========================================================*/

    private JFrame getFrame() {
        if (UtilConsoleGlobals.getActivatedFrame() != null)
            return UtilConsoleGlobals.getActivatedFrame();
	    return new JFrame();
    }

	private void initReadResponse()
	    throws IOException {

		readHeader();
		readBody();
	}

    private int readLineFromStream(InputStream is, byte line[],
                       int startpos, int len) throws IOException {
	    //return is.readLine(line, startpos, len);
        int pos = startpos;
        int count = 0;
        while (len > 0)
        {
          int nRead = httpIn.read(line, pos, 1);
          if (nRead == -1)
            break;
          count++;
          if (line[pos] == '\n') {
            break;
          }
          pos++;
        }
        return count > 0 ? count : -1;
    }

	private void readHeader() throws IOException
	{
		// Read the status line of response and parse for
		// Errors.
		byte[] headerLine = new byte[1096];
		int nRead = readLineFromStream(httpIn, headerLine, 0, 1096);

        //System.out.println("XXX read " + nRead);

		if (requestFailed(new String(headerLine))) {
            Debug.println("JSSConnection Debug: in readHeader requestFailed");
			throw new IOException(getReasonPhrase(new String (headerLine)));
        }

		while (true) {
			nRead = readLineFromStream(httpIn, headerLine, 0, 1096);
			int available = httpIn.available();

			//System.out.println("Available: " + available);

			if (nRead == -1) {
				System.out.println("Unexpected end of stream");
				break;
			}

			processHeader(headerLine, nRead);

			if (endOfHeader) {
				//System.out.println("End of Header");
				break;
			} else {
			    //System.out.println("Header: " + new String(headerLine)
				//		+ ", nRead: " + nRead);
			}
		}
	}

	private boolean endOfHeader(byte[] hdr, int available) {
		if (available == 2) {
			int c1 = (int)hdr[0];
			int c2 = (int)hdr[1];

			//System.out.println("C1= " + c1);
			//System.out.println("C2= " + c2);

			return true;
		} else
			return false;
	}

	private void readBody()
	    throws IOException {

		body = new byte[bodyLen];
		totalRead = 0;
		while (totalRead < bodyLen) {
			int nRead = httpIn.read(body, totalRead, bodyLen - totalRead);
			totalRead +=  nRead;
		}
	}


	private void processHeader(byte[] buf, int nRead)
	{
		if (endOfHeader(buf, nRead)) {
			endOfHeader = true;
			return;
		}

		String hdr = new String(buf, 0, nRead);
		int index = 0;
		if (hdr.toLowerCase().startsWith("content-length: ")) {
			try {
				String length = hdr.substring(hdr.indexOf(": ") + 1);
				bodyLen = Integer.parseInt(length.trim());
				return;
			} catch (Exception e){e.printStackTrace(); }
		}
	}

	private boolean requestFailed(String header) {
		return (header.indexOf(Integer.toString(HTTP_OK_RESPONSE)) > 0) ? false: true;
	}

	private String getReasonPhrase(String header) {
		String str1 = header.substring(header.indexOf(' ') +1);
		return str1.substring(str1.indexOf(' ') +1);
	}

    class InitPasswordDialog extends AbstractDialog {
        protected ResourceBundle mResource =
          ResourceBundle.getBundle(CMSAdminResources.class.getName());
        SingleBytePasswordField pwd;
        SingleBytePasswordField pwdAgain;
        CryptoToken mToken;
        boolean tokenPasswdInit = true;
        boolean pwdSame = true;

        public InitPasswordDialog(CryptoToken token) {
            super(null,"",true, OK|CANCEL);
            setMinimumSize(300, 150);
            mToken = token;
            setTitle(mResource.getString("SSLCLIENT_INITPASSWORD_DIALOG_TITLE"));
            Container p = getContentPane();
            p.setLayout(new GridBagLayout());

            int y = 0;
            pwd = new SingleBytePasswordField();
            pwdAgain = new SingleBytePasswordField();
            JLabel pwdLbl = new JLabel();
            JLabel pwdAgainLbl = new JLabel();
            pwdLbl.setText(mResource.getString("SSLCLIENT_INITPASSWORD_PWD_LABEL"));
            pwdAgainLbl.setText(
              mResource.getString("SSLCLIENT_INITPASSWORD_PWDAGAIN_LABEL"));
            GridBagUtil.constrain(p, pwdLbl,
              0, y, 1, 1,
              0.0, 0.0,
              GridBagConstraints.EAST, GridBagConstraints.NONE);
            GridBagUtil.constrain(p, pwd,
              1, y, GridBagConstraints.REMAINDER, 1,
              1.0, 0.0,
              GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL);
            GridBagUtil.constrain(p, pwdAgainLbl,
              0, ++y, 1, 1,
              0.0, 0.0,
              GridBagConstraints.WEST, GridBagConstraints.NONE);
            GridBagUtil.constrain(p, pwdAgain,
              1, y, GridBagConstraints.REMAINDER, 1,
              1.0, 0.0,
              GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL);
/*
            GridBagUtil.constrain(p, pwd,
              0, ++y, 1, 1,
              1.0, 0.0,
              GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
              0, 0, 0, 0);
*/

            pack();
        }

        protected void okInvoked() {
            if (!pwd.getText().equals(pwdAgain.getText())) {
                pwdSame = false;
                dispose();
                return;
            }

            try {
                mToken.initPassword(null, getPassword());
                dispose();
            } catch (Exception e) {
                tokenPasswdInit = false;
            }
        }

        public boolean isPwdSame() {
            return pwdSame;
        }

        public boolean isTokenInit() {
            return tokenPasswdInit;
        }

        public void setVisible(boolean visible) {
            pack();
            pwd.grabFocus();
            super.setVisible(visible);
        }

        public Password getPassword() {
            Password jssPwd = new Password(pwd.getText().toCharArray());
            return jssPwd;
        }
    }

	class GetPasswordDialog extends AbstractDialog {

        MultilineLabel enterPwdLabel = new MultilineLabel();
	    protected ResourceBundle mResource =
          ResourceBundle.getBundle(CMSAdminResources.class.getName());
        SingleBytePasswordField pwd;
        public GetPasswordDialog() {
            super(null,"",true, OK|CANCEL);
	        setTitle(mResource.getString("SSLCLIENT_PASSWORD_DIALOG_TITLE"));
            Container p = getContentPane();
            p.setLayout(new GridBagLayout());

            int y = 0;
            GridBagUtil.constrain(p, enterPwdLabel,
               0, y, 1, 1,
               1.0, 0.0,
               GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
               0, 0, 0, 0);

            pwd = new SingleBytePasswordField();
            GridBagUtil.constrain(p, pwd,
              0, ++y, 1, 1,
              1.0, 0.0,
              GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
              0, 0, 0, 0);

            pack();
        }

        public void setVisible(boolean visible) {
            pack();
            pwd.grabFocus();
            super.setVisible(visible);
        }

	    public void setPasswordInfo(PasswordCallbackInfo info, boolean getPwdAgain) {
            if (getPwdAgain)
                enterPwdLabel.setText(mResource.getString(
                  "SSLCLIENT_PASSWORDAGAIN_DIALOG_LABEL")+" "+info.getName()+":");
            else
                enterPwdLabel.setText(mResource.getString(
                  "SSLCLIENT_PASSWORD_DIALOG_LABEL")+" "+ info.getName()+":");
            Debug.println(info.getName());
        }

        public Password getPassword() {
            Password jssPwd = new Password(pwd.getText().toCharArray());
            return jssPwd;
        }
    }


	class SelectCertDialog extends AbstractDialog {

        JComboBox certList = new JComboBox();
	    protected ResourceBundle mResource = ResourceBundle.getBundle(
          CMSAdminResources.class.getName());
        public SelectCertDialog() {
            super(null,"", true, OK|CANCEL);
	        setTitle(mResource.getString("SSLCLIENT_CERTSELECT_DIALOG_TITLE"));

            Container p = getContentPane();
            p.setLayout(new GridBagLayout());

            int y = 0;
            GridBagUtil.constrain(p, new JLabel(
              mResource.getString("SSLCLIENT_CERTSELECT_DIALOG_LABEL")),
              0, y, 1, 1,
              1.0, 0.0,
              GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
              0, 0, 0, 0);

            GridBagUtil.constrain(p, certList,
              0, ++y, 1, 1,
              1.0, 0.0,
              GridBagConstraints.WEST, GridBagConstraints.HORIZONTAL,
              0, 0, 0, 0);
            pack();
        }

        public void setCertList(Vector nicknames) {
            certList.removeAllItems();
            Enumeration enum1 = nicknames.elements();
            while (enum1.hasMoreElements()) {
                certList.insertItemAt(enum1.nextElement(), 0);
            }
            try {
                certList.setSelectedIndex(0);
            } catch (Exception e) {
            }
        }

        public String getSelectedCert() {
            return certList.getSelectedItem().toString();
        }

	}

}
