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

import com.netscape.management.nmclf.*;
import com.netscape.management.client.util.*;

import java.awt.*;
import java.util.*;
import java.text.*;
import javax.swing.*;

import org.mozilla.jss.ssl.SSLCertificateApprovalCallback.ValidityStatus;
import org.mozilla.jss.ssl.SSLCertificateApprovalCallback.ValidityItem;

import java.security.cert.*;

/**
 * A dialog that displays a certificate, with its details.
 */
class ViewCertificateDialog extends AbstractDialog implements SuiConstants {

    private JTabbedPane infoPane = new JTabbedPane();
    private ResourceSet _resource = new ResourceSet("com.netscape.management.client.security.securityResource");
    private JSplitPane certInfoView ;


    private String i18n(String id) {
        return _resource.getString("ViewCertificateDialog", id);
    }

    /**
     * Create a certificate dialog
     * @param parent             the owner of the dialog
     * @param cert               certificate chain
     * @param certChain_errCode  cert chain errors (0 if no errors)
     * @param serverCert_errCode server cert errors (0 if no errors)
     * @param resource           propertie resource bundle
     *
     */
    public ViewCertificateDialog(Frame parent, X509Certificate cert,
                                 ValidityStatus status) {

        super(parent, "", true, OK /*| HELP*/);
        setTitle(_resource.getString("CertificateDetailDialog", "title"));

        getContentPane().add(infoPane);

        setCertificate(cert, status);

        setMinimumSize(400, 400);
        if (parent == null) {
            ModalDialogUtil.setCenteredDialog(this);
        }
        pack();
    }

    protected void okInvoked() {
        setVisible(false);
    }

    //my own stupid little parser, if JSS or sun publish those
    //apis...  I woudn't have to do this.
    private void extractNameFromDN(String dn, Hashtable store){
        Debug.println(6, "ViewCertificateDialog.extractNameFromDN: dn = " + dn);
        String[] aRDNs = netscape.ldap.LDAPDN.explodeDN(dn,/*values only*/false);
        if (aRDNs!=null) {
            for (int i=0;i<aRDNs.length;i++) {
                if (aRDNs[i]!=null){
                    Debug.println(6, "ViewCertificateDialog.extractNameFromDN RDN: " + aRDNs[i]);
                    int loc = aRDNs[i].indexOf('=');
                    String key =  aRDNs[i].substring(0, loc);
                    String val =  aRDNs[i].substring(loc+1, aRDNs[i].length());
                    store.put(key.trim(), val.trim());
                } else {
                    Debug.println(6, "ViewCertificateDialog.extractNameFromDN: ERROR - Unable to read RDN");
                }
            }
            
        } else {
            Debug.println(6, "ViewCertificateDialog.extractNameFromDN: ERROR - Unable to read DN");
        }
    }

    private static final String digits = "0123456789abcdef";
    private String hexify(byte[] hexBinary) {

        if (hexBinary.length == 0)
            return "0";

        StringBuffer buf = new StringBuffer(hexBinary.length * 2);
        for (int i = 0; i < hexBinary.length; i++) {
            buf.append(digits.charAt((hexBinary[i] >> 4) & 0x0f));
            buf.append(digits.charAt(hexBinary[i] & 0x0f));
            if (i != hexBinary.length) {
                buf.append(':');
            } else {
                buf.append('0');
            }
        }

        return buf.toString();
    }

    public void setCertificate(X509Certificate cert,
                               ValidityStatus status)
    {
        Hashtable certInfo = new Hashtable();
        try {
            certInfo.put("SUBJECT_DN", cert.getSubjectDN().toString());
            certInfo.put("ISSUER_DN", cert.getIssuerDN().toString());
            certInfo.put("SERIAL", cert.getSerialNumber().toString());
            certInfo.put("VERSION", Integer.toString(cert.getVersion()));

            SimpleDateFormat formatter = new SimpleDateFormat ("EEE MMM dd HH:mm:ss yyyy");

            certInfo.put("BEFOREDATE", formatter.format(cert.getNotBefore()));
            certInfo.put("AFTERDATE", formatter.format(cert.getNotAfter()));
            certInfo.put("SIGNATURE", cert.getSigAlgName());
            if (cert.getPublicKey() != null && cert.getPublicKey().getAlgorithm() != null) {
                certInfo.put("KEYTYPE", cert.getPublicKey().getAlgorithm());
            }
            //certInfo.put("FINGERPRINT", hexify(cert.getSignature()));
            //certInfo.put(, cert);

            Hashtable subject = new Hashtable();
            Hashtable issuer  = new Hashtable();

            extractNameFromDN(cert.getSubjectDN().toString(), subject);
            extractNameFromDN(cert.getIssuerDN().toString(), issuer);

            certInfo.put("SUBJECT", subject);
            certInfo.put("ISSUER", issuer);

            Hashtable reason = new Hashtable();

            Enumeration errors = status.getReasons();
            int i=0;
            while (errors.hasMoreElements()) {
                i++;
                ValidityItem item = (ValidityItem)errors.nextElement();
                //need to do number to error message mapping...
                String errorString = "";

                switch (item.getReason()) {
                case ValidityStatus.BAD_KEY :                      errorString = i18n("BAD_KEY"); break;
                case ValidityStatus.BAD_SIGNATURE :                errorString = i18n("BAD_SIGNATURE"); break;
                case ValidityStatus.CA_CERT_INVALID :              errorString = i18n("CA_CERT_INVALID"); break;
                case ValidityStatus.CERT_NOT_IN_NAME_SPACE :       errorString = i18n("CERT_NOT_IN_NAME_SPACE"); break;
                case ValidityStatus.CERT_STATUS_SERVER_ERROR :     errorString = i18n("CERT_STATUS_SERVER_ERROR"); break;
                case ValidityStatus.EXPIRED_ISSUER_CERTIFICATE :   errorString = i18n("EXPIRED_ISSUER_CERTIFICATE"); break;
                case ValidityStatus.INADEQUATE_CERT_TYPE :         errorString = i18n("INADEQUATE_CERT_TYPE"); break;
                case ValidityStatus.INADEQUATE_KEY_USAGE :         errorString = i18n("INADEQUATE_KEY_USAGE"); break;
                case ValidityStatus.PATH_LEN_CONSTRAINT_INVALID :  errorString = i18n("PATH_LEN_CONSTRAINT_INVALID"); break;
                case ValidityStatus.REVOKED_CERTIFICATE :          errorString = i18n("REVOKED_CERTIFICATE"); break;
                case ValidityStatus.UNKNOWN_ISSUER :               errorString = i18n("UNKNOWN_ISSUER"); break;
                case ValidityStatus.UNTRUSTED_CERT :               errorString = i18n("UNTRUSTED_CERT"); break;
                case ValidityStatus.UNTRUSTED_ISSUER :             errorString = i18n("UNTRUSTED_ISSUER"); break;
                case ValidityStatus.BAD_CERT_DOMAIN :              errorString = i18n("BAD_CERT_DOMAIN"); break;
                default:                            errorString = i18n("UNKOWN"); break; //shouldn't get here, if it did something is goofy in JSS
                }


                reason.put(Integer.toString(item.getReason()), errorString);
                Debug.println("ViewCertificateDialog.getCertificate: ERROR = "+item.getReason()+":"+errorString);
            }
            certInfo.put("REASONS", reason);

            CertificateInfoPanels certInfoPane = new CertificateInfoPanels(certInfo);
            /*certInfoPane.setDefaultBorder(new CompoundBorder(
                new MatteBorder(DIFFERENT_COMPONENT_SPACE,
                DIFFERENT_COMPONENT_SPACE, DIFFERENT_COMPONENT_SPACE,
                DIFFERENT_COMPONENT_SPACE, getContentPane().getBackground()),
                new BevelBorder(BevelBorder.LOWERED, Color.white,
                getContentPane().getBackground(), Color.black,
                Color.black)));*/

            infoPane.removeAll();
            infoPane.add(_resource.getString("CertificateDetailDialog", "generalTitle") , certInfoPane.getGeneralInfo());
            infoPane.add(_resource.getString("CertificateDetailDialog", "detailTitle"), certInfoPane.getDetailInfo());

            Debug.println(9, certInfo.toString());
        } catch (Exception e) {
            SecurityUtil.printException("ViewCertificateDialog::setCertificate(...)",e);
        }

    }
}
