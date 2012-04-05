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
//package com.netscape.management.client.security;
package com.netscape.admin.certsrv.connection;

import com.netscape.management.nmclf.SuiConstants;
import com.netscape.management.nmclf.SuiLookAndFeel;
import com.netscape.management.client.util.*;
import com.netscape.admin.certsrv.ug.*;

import java.awt.event.*;
import java.awt.*;
import javax.swing.*;
import java.io.*;
import java.util.*;
import java.net.*;
import java.text.*;
import java.security.cert.X509Certificate;
import com.netscape.admin.certsrv.*;
import com.netscape.certsrv.common.*;

import org.mozilla.jss.ssl.SSLCertificateApprovalCallback.ValidityStatus;

/**
 * Dialog box that prompts user to either accept or reject
 * an untrusted certificate.
 */
public class PromptForTrustDialog extends AbstractDialog implements SuiConstants {

    private static boolean certIsAccepted = false;
    private static boolean acceptedForSingleSession = false;
    private X509Certificate mCert;

    private UserConfirmationActionListener buttonActionListener =
            new UserConfirmationActionListener();
     protected ResourceBundle mResource;
    //static ResourceSet _resource = new ResourceSet("com.netscape.admin.certsrv.connection.ServerAuthResource");

    CertViewDialog viewCertDialog;
    //ViewCertificateDialog viewCertDialog;
    JCheckBox oneSession;


    /**
     * create a dialog that prompt user to either accept or reject an untrusted certificate
     * @param parent             the owner of the dialog
     * @param cert               certificate chain
     * @param certChain_errCode  cert chain errors (0 if no errors)
     * @param serverCert_errCode server cert errors (0 if no errors)
     *
     *
     */
    public PromptForTrustDialog(Frame parent, X509Certificate cert,
            ValidityStatus status) {
        super(parent, "", true);
	 mResource = ResourceBundle.getBundle(
		CMSAdminResources.class.getName());
        mCert = cert;

        setTitle(mResource.getString("SSLCLIENT_TRUST_DIALOG_TITLE"));

        getContentPane().setLayout(new GridBagLayout());


        //Add action button pane first so the accept button will
        //get default focus.  Already try various way with *Focus() call
        //none of them work.
        GridBagUtil.constrain(getContentPane(), createActionButtons(),
                0, 1, 1, 1, 0.0, 0.0, GridBagConstraints.SOUTHEAST,
                GridBagConstraints.NONE, 0, 0, 0, 0);

        GridBagUtil.constrain(getContentPane(), siteAlert(), 0, 0, 1,
                1, 1.0, 1.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, VERT_WINDOW_INSET,
                VERT_WINDOW_INSET, 0, 0);

        //viewCertDialog = new ViewCertificateDialog(parent, cert, status);
        viewCertDialog = new CertViewDialog((JFrame)parent);

        setMinimumSize(400, 250);
        if (parent == null) {
            ModalDialogUtil.setCenteredDialog(this);
        }
        pack();
    }


    /**
      * Handles all the action (Ok, Accept, Reject, and Help)
      *
      */
    class UserConfirmationActionListener implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            if (e.getActionCommand().equals("ACCEPT")) {
                certIsAccepted = true;
                setVisible(false);
            } else if (e.getActionCommand().equals("REJECT")) {
                certIsAccepted = false;
                setVisible(false);
            } else if (e.getActionCommand().equals("VIEWCERT")) {
                String certContent = getPrettyPrint(mCert);
                viewCertDialog.showDialog("", certContent);
            }
        }
    }

    private final static String spaces =
        "                                                 " +
        "                                                 " +
        "                                                 " +
        "                                                 " +
        "                                                 ";
    private static final char[] hexdigits = {
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
        'A', 'B', 'C', 'D', 'E', 'F'
    };

    private String indent(int size) {
        return spaces.substring(0, size);
    }

    private String getPrettyPrint(X509Certificate cert) {
        String subjectdn = cert.getSubjectDN().toString();
        String issuerdn = cert.getIssuerDN().toString();
        String serial = cert.getSerialNumber().toString();
        SimpleDateFormat formatter = new SimpleDateFormat("EEE MMM dd HH:mm:ss yyyy");
        String before = formatter.format(cert.getNotBefore());
        String after = formatter.format(cert.getNotAfter());
        String fingerprint = getHexString(cert.getSignature(), 16, 16, ":");
        String str = "Subject name: "+subjectdn+"\n"+
          "Issuer name: "+issuerdn+"\n"+"Serial number: "+serial+"\n"+
          "Validity: "+before+" to "+after+"\n"+"Signature:\n"+
          fingerprint+"\n";
        return str;
    }

    private String getHexString(byte[] in, int indentSize, int lineLen,
      String separator) {
        StringBuffer sb = new StringBuffer();
        int hexCount = 0;
        char c[];
        int j = 0;

        if (lineLen == 0) {
            c = new char[in.length * 3 + 1];
        } else {
            c = new char[lineLen * 3 + 1];
        }

        char sep = separator.charAt(0);

        sb.append(indent(indentSize));
        for (int i = 0; i < in.length; i++) {
            if (lineLen > 0 && hexCount == lineLen) {
                c[j++] = '\n';
                sb.append(c, 0, j);
                sb.append(indent(indentSize));
                hexCount = 0;
                j = 0;
            }
            byte x = in[i];

            // output hex digits to buffer
            c[j++] = hexdigits[(char) ((x >> 4) & 0xf)];
            c[j++] = hexdigits[(char) (x & 0xf)];

            // if not last char, output separator
            if (i != in.length - 1) {
                c[j++] = sep;
            }

            hexCount++;
        }
        if (j > 0) {
            c[j++] = '\n';
            sb.append(c, 0, j);
        }
        //        sb.append("\n");

        return sb.toString();
    }

    /**
      * @return true if certificate is accepted
      */
    public boolean isCertAccepted() {
        return certIsAccepted;
    }

    /**
      * @return true certificate should only be accept for a single session
      */
    public boolean isAcceptedForOneSession() {
        return oneSession.isSelected();
    }


    /**
      * Allow reuse of this dialog, if it is not disposed.
      * @param cert               certificate chain
      * @param certChain_errCode  cert chain errors (0 if no errors)
      * @param serverCert_errCode server cert errors (0 if no errors)
      *
      */
    public void setCertificateInfo(X509Certificate cert,
                                   ValidityStatus status) {
        //viewCertDialog.setCertificate(cert, status);
     }


    /**
      * Create a warning message panel
      */
    private JPanel siteAlert() {
        JPanel notTrustedSiteWarning = new JPanel();
        notTrustedSiteWarning.setLayout(new GridBagLayout());

        JLabel warningImage = new JLabel(UIManager.getIcon("OptionPane.warningIcon"));
        MultilineLabel warningMsg = new MultilineLabel(
                mResource.getString("SSLCLIENT_TRUST_DIALOG_WARNMSG"));
        oneSession = new JCheckBox(
                mResource.getString("SSLCLIENT_TRUST_DIALOG_ACCEPTONESESSION"),
                false);

        GridBagUtil.constrain(notTrustedSiteWarning, warningImage, 0,
                0, 1, 1, 0.0, 0.0, GridBagConstraints.NORTHWEST,
                GridBagConstraints.NONE, 0, 0, 0,
                DIFFERENT_COMPONENT_SPACE);

        GridBagUtil.constrain(notTrustedSiteWarning, warningMsg, 1, 0,
                1, 1, 1.0, 0.0, GridBagConstraints.NORTHWEST,
                GridBagConstraints.BOTH, 0, 0,
                DIFFERENT_COMPONENT_SPACE, VERT_WINDOW_INSET);

        GridBagUtil.constrain(notTrustedSiteWarning, oneSession, 1, 1,
                1, 1, 0.0, 0.0, GridBagConstraints.SOUTHWEST,
                GridBagConstraints.NONE, 0, 0, 0, VERT_WINDOW_INSET);

        GridBagUtil.constrain(notTrustedSiteWarning,
                Box.createVerticalGlue(), 1, 2, 2, 1, 1.0, 1.0,
                GridBagConstraints.NORTH, GridBagConstraints.BOTH, 0,
                0, 0, 0);
        return notTrustedSiteWarning;
    }

    JButton accept;
    public void setVisible(boolean visible) {
        if (visible) {
            accept.grabFocus();
            setDefaultButton(accept);
        }
        super.setVisible(visible);
    }

    /**
      * create all the action buttons (Accept, Reject, View Certificate, and Help)
      */
    private JPanel createActionButtons() {
        JPanel buttonPanel = new JPanel();
        buttonPanel.setLayout(new GridBagLayout());

        accept = JButtonFactory.create(
                                       mResource.getString("SSLCLIENT_TRUST_DIALOG_ACCEPT"),
                                       buttonActionListener, "ACCEPT");
        accept.registerKeyboardAction(buttonActionListener, "ACCEPT",
                                      KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0),
                                      JComponent.WHEN_IN_FOCUSED_WINDOW);

        JButton reject = JButtonFactory.create(
                                              mResource.getString("SSLCLIENT_TRUST_DIALOG_REJECT"),
                                               buttonActionListener, "REJECT");
        reject.registerKeyboardAction(buttonActionListener, "REJECT",
                                      KeyStroke.getKeyStroke(KeyEvent.VK_R, 0),
                                      JComponent.WHEN_IN_FOCUSED_WINDOW);

        JButton viewCert = JButtonFactory.create(
                                                 mResource.getString("SSLCLIENT_TRUST_DIALOG_VIEWCERT"),  buttonActionListener, "VIEWCERT");
        viewCert.registerKeyboardAction(buttonActionListener, "VIEWCERT",
                                        KeyStroke.getKeyStroke(KeyEvent.VK_V, 0),
                                        JComponent.WHEN_IN_FOCUSED_WINDOW);
        JButtonFactory.resizeGroup(accept, reject);

        int x = 0;
        GridBagUtil.constrain(buttonPanel, accept, x, 0, 1, 1, 0.0,
                              0.0, GridBagConstraints.NORTH,
                              GridBagConstraints.BOTH, DIFFERENT_COMPONENT_SPACE, 0,
                              0, COMPONENT_SPACE);

        GridBagUtil.constrain(buttonPanel, reject, ++x, 0, 1, 1, 0.0,
                0.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, DIFFERENT_COMPONENT_SPACE, 0,
                0, COMPONENT_SPACE);

        GridBagUtil.constrain(buttonPanel, viewCert, ++x, 0, 1, 1, 0.0,
                0.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, DIFFERENT_COMPONENT_SPACE, 0,
                0, DIFFERENT_COMPONENT_SPACE);

        return buttonPanel;
    }
}
