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
package com.netscape.cms.profile.constraint;

import java.math.BigInteger;
import java.util.Date;
import java.util.Enumeration;
import java.util.Locale;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.dbs.certdb.ICertRecord;
import com.netscape.certsrv.dbs.certdb.ICertRecordList;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.profile.ERejectException;
import com.netscape.certsrv.profile.IPolicyDefault;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;
import com.netscape.cms.profile.def.NoDefault;

import netscape.security.x509.CertificateSubjectName;
import netscape.security.x509.CertificateX509Key;
import netscape.security.x509.X500Name;
import netscape.security.x509.X509CertImpl;
import netscape.security.x509.X509CertInfo;
import netscape.security.x509.X509Key;

/**
 * This constraint is to check for publickey uniqueness.
 * The config param "allowSameKeyRenewal" enables the
 * situation where if the publickey is not unique, and if
 * the subject DN is the same, that is a "renewal".
 *
 * Another "feature" that is quoted out of this code is the
 * "revokeDupKeyCert" option, which enables the revocation
 * of certs that bear the same publickey as the enrolling
 * request. Since this can potentially be abused, it is taken
 * out and preserved in comments to allow future refinement.
 *
 * @version $Revision$, $Date$
 */
public class UniqueKeyConstraint extends EnrollConstraint {
    /*
    public static final String CONFIG_REVOKE_DUPKEY_CERT =
    	"revokeDupKeyCert";
    boolean mRevokeDupKeyCert = false;
    */
    public static final String CONFIG_ALLOW_SAME_KEY_RENEWAL =
            "allowSameKeyRenewal";
    boolean mAllowSameKeyRenewal = false;
    public ICertificateAuthority mCA = null;

    public UniqueKeyConstraint() {
        super();
        /*
        addConfigName(CONFIG_REVOKE_DUPKEY_CERT);
        */
        addConfigName(CONFIG_ALLOW_SAME_KEY_RENEWAL);
    }

    public void init(IProfile profile, IConfigStore config)
            throws EProfileException {
        super.init(profile, config);
        mCA = (ICertificateAuthority)
                CMS.getSubsystem(CMS.SUBSYSTEM_CA);
    }

    public IDescriptor getConfigDescriptor(Locale locale, String name) {
        /*
        if (name.equals(CONFIG_REVOKE_DUPKEY_CERT)) {
        	return new Descriptor(IDescriptor.BOOLEAN, null, "false",
        		  CMS.getUserMessage(locale, "CMS_PROFILE_CONFIG_REVOKE_DUPKEY_CERT"));
        }
        */
        if (name.equals(CONFIG_ALLOW_SAME_KEY_RENEWAL)) {
            return new Descriptor(IDescriptor.BOOLEAN, null, "false",
                    CMS.getUserMessage(locale, "CMS_PROFILE_CONFIG_ALLOW_SAME_KEY_RENEWAL"));
        }
        return null;
    }

    public String getDefaultConfig(String name) {
        return null;
    }

    /**
     * Validates the request. The request is not modified
     * during the validation.
     *
     * It will try to capture orig cert expiration info for renewal later.
     * Renewal can be either renewal with same key or new key.
     *
     * In case of renewing with same key, the old cert record
     * can be retrieved and used to fill original info such as
     * original expiration date for use with RenewGracePeriodConstraint.
     *
     * In case of renewing with new key, it would be no different from
     * regular enrollment
     *
     * Search by ICertRecord.ATTR_X509CERT_PUBLIC_KEY_DATA
     * would tell us if its reusing the same key or not.
     * If any cert with the same key in the repository is found
     * to be revoked, then the request is rejected
     *
     * This contraint has to go before the RenewGracePeriodConstraint,
     * but after any of the SubjectName Default and Constraint
     */
    public void validate(IRequest request, X509CertInfo info)
            throws ERejectException {
        String method = "UniqueKeyConstraint: validate: ";
        String msg = "";
        boolean rejected = false;
        int size = 0;
        ICertRecordList list;

        /*
        mRevokeDupKeyCert =
        getConfigBoolean(CONFIG_REVOKE_DUPKEY_CERT);
        */
        mAllowSameKeyRenewal = getConfigBoolean(CONFIG_ALLOW_SAME_KEY_RENEWAL);
        msg = msg + ": allowSameKeyRenewal=" + mAllowSameKeyRenewal + ";";
        CMS.debug(method + msg);

        try {
            CertificateX509Key infokey = (CertificateX509Key)
                    info.get(X509CertInfo.KEY);
            X509Key key = (X509Key)
                    infokey.get(CertificateX509Key.KEY);

            // check for key uniqueness
            byte pub[] = key.getEncoded();
            String pub_s = escapeBinaryData(pub);
            String filter = "(" + ICertRecord.ATTR_X509CERT_PUBLIC_KEY_DATA + "=" + pub_s + ")";
            list =
                    mCA.getCertificateRepository().findCertRecordsInList(filter, null, 10);
            size = list.getSize();

        } catch (Exception e) {
            throw new ERejectException(
                    CMS.getUserMessage(
                            getLocale(request),
                            "CMS_PROFILE_INTERNAL_ERROR", method + e.toString()));
        }

        /*
         * It does not matter if the corresponding cert's status
         * is valid or not, if mAllowSameKeyRenewal is false,
         * we don't want a key that was once generated before
         */
        if (size > 0) {
            CMS.debug(method + "found existing cert with same key");

            /*
                The following code revokes the existing certs that have
            	the same public key as the one submitted for enrollment
            	request.  However, it is not a good idea due to possible
            	abuse.  It is therefore commented out.  It is still
            	however still maintained for possible utilization at later
            	time

            	// if configured to revoke duplicated key
            	//    revoke cert
            	if (mRevokeDupKeyCert) {
            		try {
            			Enumeration e = list.getCertRecords(0, size-1);
            			while (e != null && e.hasMoreElements()) {
            				ICertRecord rec = (ICertRecord) e.nextElement();
            				X509CertImpl cert = rec.getCertificate();

            				// revoke the cert
            				BigInteger serialNum = cert.getSerialNumber();
            				ICAService service = (ICAService) mCA.getCAService();

					RevokedCertImpl crlEntry =
            					formCRLEntry(serialNum, RevocationReason.KEY_COMPROMISE);
            				service.revokeCert(crlEntry);
            				CMS.debug("UniqueKeyConstraint: certificate with duplicate publickey revoked successfully");
            			}
            		} catch (Exception ex) {
            			CMS.debug("UniqueKeyConstraint: error in revoke dupkey cert");
            		}
            	} // revoke dupkey cert turned on
            */

            if (mAllowSameKeyRenewal == true) {
                X500Name sjname_in_db = null;
                X500Name sjname_in_req = null;

                try {
                    // get subject of request
                    CertificateSubjectName subName =
                            (CertificateSubjectName) info.get(X509CertInfo.SUBJECT);

                    if (subName != null) {

                        sjname_in_req =
                                (X500Name) subName.get(CertificateSubjectName.DN_NAME);
                        CMS.debug(method +" cert request subject DN =" + sjname_in_req.toString());
                        Enumeration<ICertRecord> e = list.getCertRecords(0, size - 1);
                        Date latestOrigNotAfter = null;
                        Date origNotAfter = null;
                        boolean first = true;
                        while (e != null && e.hasMoreElements()) {
                            CMS.debug(method +  msg);
                            ICertRecord rec = e.nextElement();
                            BigInteger serial = rec.getSerialNumber();
                            msg = msg + "existing cert with same key found: " + serial.toString() + ";";

                            if (rec.getStatus().equals(ICertRecord.STATUS_REVOKED)
                                    || rec.getStatus().equals(ICertRecord.STATUS_REVOKED_EXPIRED)) {
                                msg = msg + "revoked cert cannot be renewed;";
                                CMS.debug(method + msg);
                                rejected = true;
                                // this has to break
                                break;
                            }
                            if (!rec.getStatus().equals(ICertRecord.STATUS_VALID)
                                    && !rec.getStatus().equals(ICertRecord.STATUS_EXPIRED)) {
                                CMS.debug(method + "invalid cert cannot be renewed; continue;" + serial.toString());
                                // can still find another one to renew
                                continue;
                            }
                            // only VALID or EXPIRED certs could have reached here
                            X509CertImpl origCert = rec.getCertificate();
                            String certDN =
                                    origCert.getSubjectDN().toString();
                            CMS.debug(method + " cert retrieved from ldap has subject DN =" + certDN);

                            sjname_in_db = new X500Name(certDN);

                            if (sjname_in_db.equals(sjname_in_req) == false) {
                                msg = msg + "subject name not match in same key renewal;";
                                rejected = true;
                                break;
                            } else {
                                CMS.debug("subject name match in same key renewal");
                            }

                            // find the latest expiration date to keep for
                            // Renewal Grace Period Constraint later
                            origNotAfter = origCert.getNotAfter();
                            CMS.debug(method + "origNotAfter =" + origNotAfter.toString());
                            if (first) {
                                latestOrigNotAfter = origNotAfter;
                                first = false;
                            } else if (latestOrigNotAfter.before(origNotAfter)) {
                                CMS.debug(method + "newer cert found");
                                latestOrigNotAfter = origNotAfter;
                            }

                            // yes, this could be overwritten by later
                            // found cert(s) that has violations
                            rejected = false;
                        } // while

                        if (latestOrigNotAfter != null) {
                            String existingOrigExpDate_s = request.getExtDataInString("origNotAfter");
                            if (existingOrigExpDate_s != null) {
                                // make sure not to interfere with renewal by serial
                                CMS.debug(method +
                                        " original cert expiration date already exists. Not overriding.");
                            } else {
                                // set origNotAfter for RenewGracePeriodConstraint
                                CMS.debug(method + "setting latest original cert expiration in request");
                                request.setExtData("origNotAfter", BigInteger.valueOf(latestOrigNotAfter.getTime()));
                            }
                        }
                    } else { //subName is null
                        msg =  msg +"subject name not found in cert request info;";
                        rejected = true;
                    }
                } catch (Exception ex1) {
                    CMS.debug(method +  msg + ex1.toString());
                    rejected = true;
                } // try

            } else {
                msg = msg + "found existing cert with same key;";
                rejected = true;
            }// allowSameKeyRenewal
        } // (size > 0)

        if (rejected == true) {
            CMS.debug(method + " rejected: " + msg);
            throw new ERejectException(msg);
        } else {
            CMS.debug(method + " approved");
        }
    }

    /**
     * make a CRL entry from a serial number and revocation reason.
     *
     * @return a RevokedCertImpl that can be entered in a CRL.
     *
     *         protected RevokedCertImpl formCRLEntry(
     *         BigInteger serialNo, RevocationReason reason)
     *         throws EBaseException {
     *         CRLReasonExtension reasonExt = new CRLReasonExtension(reason);
     *         CRLExtensions crlentryexts = new CRLExtensions();
     *
     *         try {
     *         crlentryexts.set(CRLReasonExtension.NAME, reasonExt);
     *         } catch (IOException e) {
     *         CMS.debug("CMSGW_ERR_CRL_REASON "+e.toString());
     *
     *         // throw new ECMSGWException(
     *         // CMS.getLogMessage("CMSGW_ERROR_SETTING_CRLREASON"));
     *
     *         }
     *         RevokedCertImpl crlentry =
     *         new RevokedCertImpl(serialNo, CMS.getCurrentDate(),
     *         crlentryexts);
     *
     *         return crlentry;
     *         }
     */

    public String getText(Locale locale) {
        String params[] = {
        /*
                        getConfig(CONFIG_REVOKE_DUPKEY_CERT),
        */
        };

        return CMS.getUserMessage(locale,
                "CMS_PROFILE_CONSTRAINT_ALLOW_SAME_KEY_RENEWAL_TEXT", params);
    }

    public static String escapeBinaryData(byte data[]) {
        StringBuffer sb = new StringBuffer();

        for (int i = 0; i < data.length; i++) {
            int v = 0xff & data[i];
            sb.append("\\");
            sb.append((v < 16 ? "0" : ""));
            sb.append(Integer.toHexString(v));
        }
        return sb.toString();
    }

    public boolean isApplicable(IPolicyDefault def) {
        if (def instanceof NoDefault)
            return true;
        if (def instanceof UniqueKeyConstraint)
            return true;

        return false;
    }

}
