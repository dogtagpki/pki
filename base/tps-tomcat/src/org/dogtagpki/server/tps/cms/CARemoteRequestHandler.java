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
// (C) 2014 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package org.dogtagpki.server.tps.cms;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.util.Hashtable;
import java.util.List;

import netscape.security.x509.AuthorityKeyIdentifierExtension;
import netscape.security.x509.KeyIdentifier;
import netscape.security.x509.PKIXExtensions;
import netscape.security.x509.RevocationReason;
import netscape.security.x509.SubjectKeyIdentifierExtension;
import netscape.security.x509.X509CertImpl;

import org.dogtagpki.server.connector.IRemoteRequest;
import org.dogtagpki.server.tps.TPSSubsystem;
import org.dogtagpki.server.tps.engine.TPSEngine;
import org.dogtagpki.tps.main.TPSBuffer;
import org.dogtagpki.tps.main.Util;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.CryptoManager.NotInitializedException;
import org.mozilla.jss.crypto.X509Certificate;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.cmscore.connector.HttpConnector;
import com.netscape.cmsutil.http.HttpResponse;
import com.netscape.cmsutil.util.Utils;
import com.netscape.cmsutil.xml.XMLObject;

/**
 * CARemoteRequestHandler is a class representing remote requests
 * offered by the Certificate Authority (CA)
 *
 * @author cfu
 */
public class CARemoteRequestHandler extends RemoteRequestHandler
{
    public CARemoteRequestHandler(String connID)
            throws EBaseException {
        if (connID == null) {
            throw new EBaseException("CARemoteRequestHandler: CARemoteRequestHandler(): connID null.");
        }
        connid = connID;
    }

    /**
     * enrollCertificate enrolls a certificate in the CA
     *
     * @param pubKeybuf public key for enrollment
     * @param uid uid for enrollment
     * @param cuid token id
     *
     * @returns CAEnrollCertResponse
     */
    public CAEnrollCertResponse enrollCertificate(
            TPSBuffer pubKeybuf,
            String uid,
            String cuid,
            String tokenType,
            String keyType)
            throws EBaseException {

        CMS.debug("CARemoteRequestHandler: enrollCertificate(): begins.");
        if (pubKeybuf == null || uid == null || cuid == null) {
            throw new EBaseException("CARemoteRequestHandler: enrollCertificate(): input parameter null.");
        }

        IConfigStore conf = CMS.getConfigStore();
        String profileId =
                conf.getString(TPSEngine.OP_ENROLL_PREFIX + "." +
                        tokenType + ".keyGen." +
                        keyType + ".ca.profileId");

        TPSSubsystem subsystem =
                (TPSSubsystem) CMS.getSubsystem(TPSSubsystem.ID);
        HttpConnector conn =
                (HttpConnector) subsystem.getConnectionManager().getConnector(connid);
        CMS.debug("CARemoteRequestHandler: enrollCertificate(): sending request to CA");
        String encodedPubKey = null;
        try {
            encodedPubKey = Util.uriEncode(CMS.BtoA(pubKeybuf.toBytesArray()));
        } catch (Exception e) {
            CMS.debug("CARemoteRequestHandler: enrollCertificate(): uriEncode of pubkey failed: " + e);
            throw new EBaseException("CARemoteRequestHandler: enrollCertificate(): uriEncode of pubkey failed: " + e);
        }
        HttpResponse resp =
                conn.send("enrollment",
                        IRemoteRequest.GET_XML + "=" +
                                true +
                                "&" + IRemoteRequest.TOKEN_CUID + "=" +
                                cuid +
                                "&" + IRemoteRequest.CA_ENROLL_screenname + "=" +
                                uid +
                                "&" + IRemoteRequest.CA_ENROLL_publickey + "=" +
                                encodedPubKey +
                                "&" + IRemoteRequest.CA_ProfileId + "=" +
                                profileId);

        String content = resp.getContent();

        CMS.debug("CARemoteRequestHandler: enrollCertificate(): got content = " + content);

        if (content != null && !content.equals("")) {
            XMLObject xmlResponse =
                    getXMLparser(content);

            Hashtable<String, Object> response =
                    new Hashtable<String, Object>();

            CMS.debug("CARemoteRequestHandler: enrollCertificate(): received:" +
                    content);

            /**
             * When a value is not found in response, keep going so we know
             * what else is missing
             * Note: serverKeygen and !serverKeygen returns different set of
             * response values so "missing" might not be bad
             */
            Integer ist = new Integer(IRemoteRequest.RESPONSE_STATUS_NOT_FOUND);
            String value = xmlResponse.getValue(IRemoteRequest.RESPONSE_STATUS_XML);
            if (value == null) {
                CMS.debug("CARemoteRequestHandler: enrollCertificate(): Status not found.");
                CMS.debug("CARemoteRequestHandler: enrollCertificate(): got content = " + content);
            } else {
                CMS.debug("CARemoteRequestHandler: enrollCertificate(): got Status = " + value);
                ist = Integer.parseInt(value);
            }
            response.put(IRemoteRequest.RESPONSE_STATUS, ist);

            value = xmlResponse.getValue("SubjectDN");
            if (value == null) {
                CMS.debug("CARemoteRequestHandler:: enrollCertificate(): response missing name-value pair for: " +
                        IRemoteRequest.CA_RESPONSE_Certificate_SubjectDN);
            } else {
                CMS.debug("CARemoteRequestHandler:: enrollCertificate(): got IRemoteRequest.CA_RESPONSE_Certificate_SubjectDN = "
                        + value);
                response.put(IRemoteRequest.CA_RESPONSE_Certificate_SubjectDN, value);
            }

            value = xmlResponse.getValue(IRemoteRequest.CA_RESPONSE_Certificate_serial);
            if (value == null) {
                CMS.debug("CARemoteRequestHandler:: enrollCertificate(): response missing name-value pair for: " +
                        IRemoteRequest.CA_RESPONSE_Certificate_serial);
            } else {
                CMS.debug("CARemoteRequestHandler:: enrollCertificate(): got IRemoteRequest.CA_RESPONSE_Certificate_serial = 0x"
                        + value);
                response.put(IRemoteRequest.CA_RESPONSE_Certificate_serial, value);
            }

            value = xmlResponse.getValue(IRemoteRequest.CA_RESPONSE_Certificate_b64);
            if (value == null) {
                CMS.debug("CARemoteRequestHandler:: enrollCertificate(): response missing name-value pair for: " +
                        IRemoteRequest.CA_RESPONSE_Certificate_b64);
            } else {
                try {
                    CMS.debug("CARemoteRequestHandler:: enrollCertificate(): got IRemoteRequest.CA_RESPONSE_Certificate_b64 = "
                            + value);
                    response.put(IRemoteRequest.CA_RESPONSE_Certificate_b64, value);
                    X509CertImpl newCert = new X509CertImpl(Utils.base64decode(value));
                    response.put(IRemoteRequest.CA_RESPONSE_Certificate_x509, newCert);
                    CMS.debug("CARemoteRequestHandler: enrollCertificate(): new cert parsed successfully");
                } catch (Exception e) {
                    // we don't exit.  Keep going.
                    CMS.debug("CARemoteRequestHandler: enrollCertificate(): exception:" + e);
                }
            }

            CMS.debug("CARemoteRequestHandler: enrollCertificate(): ends.");
            return new CAEnrollCertResponse(response);
        } else {
            CMS.debug("CARemoteRequestHandler: enrollCertificate(): no response content");
            throw new EBaseException("CARemoteRequestHandler: enrollCertificate(): no response content.");
        }
    }

    /**
     * renewCertificate renew a certificate by serial number
     *
     * @param serialno the serial number of the cert to be renewed
     * @return CARenewCertResponse
     */
    public CARenewCertResponse renewCertificate(
            BigInteger serialno,
            String tokenType,
            String keyType)
            throws EBaseException {

        CMS.debug("CARemoteRequestHandler: renewCertificate(): begins.");
        if (serialno == null) {
            throw new EBaseException("CARemoteRequestHandler: renewCertificate(): input parameter null.");
        }

        IConfigStore conf = CMS.getConfigStore();

        String profileId =
                conf.getString(TPSEngine.OP_ENROLL_PREFIX + "." +
                        tokenType + ".renewal." +
                        keyType + ".ca.profileId");

        TPSSubsystem subsystem =
                (TPSSubsystem) CMS.getSubsystem(TPSSubsystem.ID);
        HttpConnector conn =
                (HttpConnector) subsystem.getConnectionManager().getConnector(connid);
        CMS.debug("CARemoteRequestHandler: renewCertificate(): sending request to CA");
        HttpResponse resp =
                conn.send("renewal",
                        IRemoteRequest.GET_XML + "=" + true +
                                "&" + IRemoteRequest.CA_RENEWAL + "=" + true +
                                "&" + IRemoteRequest.CA_RENEWAL_SerialNum + "=" + serialno.toString() +
                                "&" + IRemoteRequest.CA_ProfileId + "=" + profileId);

        String content = resp.getContent();

        if (content != null && !content.equals("")) {
            XMLObject xmlResponse =
                    getXMLparser(content);

            Hashtable<String, Object> response =
                    new Hashtable<String, Object>();

            CMS.debug("CARemoteRequestHandler: renewCertificate(): received:" +
                    content);

            /**
             * When a value is not found in response, keep going so we know
             * what else is missing
             * Note: serverKeygen and !serverKeygen returns different set of
             * response values so "missing" might not be bad
             */
            Integer ist = new Integer(IRemoteRequest.RESPONSE_STATUS_NOT_FOUND);
            String value = xmlResponse.getValue(IRemoteRequest.RESPONSE_STATUS_XML);
            if (value == null) {
                CMS.debug("CARemoteRequestHandler: renewCertificate(): Status not found.");
                CMS.debug("CARemoteRequestHandler: renewCertificate(): got content = " + content);
            } else {
                CMS.debug("CARemoteRequestHandler: renewCertificate(): got Status = " + value);
                ist = Integer.parseInt(value);
            }
            response.put(IRemoteRequest.RESPONSE_STATUS, ist);

            value = xmlResponse.getValue("SubjectDN");
            if (value == null) {
                CMS.debug("CARemoteRequestHandler:: renewCertificate(): response missing name-value pair for: " +
                        IRemoteRequest.CA_RESPONSE_Certificate_SubjectDN);
            } else {
                CMS.debug("CARemoteRequestHandler:: renewCertificate(): got IRemoteRequest.CA_RESPONSE_Certificate_SubjectDN = "
                        + value);
                response.put(IRemoteRequest.CA_RESPONSE_Certificate_SubjectDN, value);
            }

            value = xmlResponse.getValue(IRemoteRequest.CA_RESPONSE_Certificate_serial);
            if (value == null) {
                CMS.debug("CARemoteRequestHandler:: renewCertificate(): response missing name-value pair for: " +
                        IRemoteRequest.CA_RESPONSE_Certificate_serial);
            } else {
                CMS.debug("CARemoteRequestHandler:: renewCertificate(): got IRemoteRequest.CA_RESPONSE_Certificate_serial = 0x"
                        + value);
                response.put(IRemoteRequest.CA_RESPONSE_Certificate_serial, value);
            }

            value = xmlResponse.getValue(IRemoteRequest.CA_RESPONSE_Certificate_b64);
            if (value == null) {
                CMS.debug("CARemoteRequestHandler:: renewCertificate(): response missing name-value pair for: " +
                        IRemoteRequest.CA_RESPONSE_Certificate_b64);
            } else {
                CMS.debug("CARemoteRequestHandler:: renewCertificate(): got IRemoteRequest.CA_RESPONSE_Certificate_b64 = "
                        + value);
                response.put(IRemoteRequest.CA_RESPONSE_Certificate_b64, value);
                try {
                    X509CertImpl newCert = new X509CertImpl(Utils.base64decode(value));
                    response.put(IRemoteRequest.CA_RESPONSE_Certificate_x509, newCert);
                    CMS.debug("CARemoteRequestHandler: renewCertificate(): new cert parsed successfully");
                } catch (CertificateException e) {
                    // we don't exit.  Keep going.
                    CMS.debug("CARemoteRequestHandler: renewCertificate(): exception:" + e);
                }
            }

            CMS.debug("CARemoteRequestHandler: renewCertificate(): ends.");
            return new CARenewCertResponse(response);
        } else {
            CMS.debug("CARemoteRequestHandler: renewCertificate(): no response content");
            throw new EBaseException("CARemoteRequestHandler: renewCertificate(): no response content.");
        }
    }

    /**
     * revokeCertificate provides the basic revocation of a certificate from
     * the CA
     *
     * @param serialno serial number of the cert to revoke
     * @param reason reason to revoke per definition in RevocationReason
     *
     * @returns CARevokeCertResponse
     */
    private CARevokeCertResponse revokeCertificate(
            BigInteger serialno,
            RevocationReason reason)
            throws EBaseException {

        CMS.debug("CARemoteRequestHandler: revokeCertificate(): begins.");
        if (serialno == null || reason == null) {
            throw new EBaseException("CARemoteRequestHandler: revokeCertificate(): input parameter null.");
        }

        // IConfigStore conf = CMS.getConfigStore();

        TPSSubsystem subsystem =
                (TPSSubsystem) CMS.getSubsystem(TPSSubsystem.ID);
        HttpConnector conn =
                (HttpConnector) subsystem.getConnectionManager().getConnector(connid);
        CMS.debug("CARemoteRequestHandler: revokeCertificate(): sending request to CA");
        HttpResponse resp =
                conn.send("revoke",
                        IRemoteRequest.CA_OP + "=" + IRemoteRequest.CA_REVOKE +
                                "&" + IRemoteRequest.CA_REVOCATION_REASON + "=" + reason.getCode() +
                                "&" + IRemoteRequest.CA_REVOKE_ALL + "=(" +
                                IRemoteRequest.CA_REVOKE_SERIAL + "=" + serialno.toString() + ")&" +
                                IRemoteRequest.CA_REVOKE_COUNT + "=1");
        String content = resp.getContent();

        CMS.debug("CARemoteRequestHandler: revokeCertificate(): got content = " + content);
        if (content != null && !content.equals("")) {
            Hashtable<String, Object> response =
                    parseResponse(content);

            /**
             * When a value is not found in response, keep going so we know
             * what else is missing
             */
            Integer ist = new Integer(IRemoteRequest.RESPONSE_STATUS_NOT_FOUND);
            String value = (String) response.get(IRemoteRequest.RESPONSE_STATUS);

            CMS.debug("CARemoteRequestHandler: revokeCertificate(): got status = " + value);
            ist = Integer.parseInt(value);
            if (ist != 0) {
                CMS.debug("CARemoteRequestHandler: revokeCertificate(): status not 0, getting error string... ");
                value = (String) response.get(IRemoteRequest.RESPONSE_ERROR_STRING);
                if (value == null) {
                    CMS.debug("CARemoteRequestHandler: revokeCertificate(): response missing name-value pair for: " +
                            IRemoteRequest.RESPONSE_ERROR_STRING);
                } else {
                    CMS.debug("CARemoteRequestHandler: revokeCertificate(): got IRemoteRequest.RESPONSE_ERROR_STRING = "
                            + value);
                    response.put(IRemoteRequest.RESPONSE_ERROR_STRING, value);
                }
            }
            response.put(IRemoteRequest.RESPONSE_STATUS, ist);

            CMS.debug("CARemoteRequestHandler: revokeCertificate(): ends.");
            return new CARevokeCertResponse(response);
        } else {
            CMS.debug("CARemoteRequestHandler: revokeCertificate(): no response content.");
            throw new EBaseException("CARemoteRequestHandler: revokeCertificate(): no response content.");
        }
    }

    /**
     * unrevokeCertificate provides the basic unrevocation of a certificate from
     * the CA
     *
     * @param serialno serial number of the cert to unrevoke
     *
     * @returns CARevokeCertResponse
     */
    private CARevokeCertResponse unrevokeCertificate(
            BigInteger serialno)
            throws EBaseException {

        CMS.debug("CARemoteRequestHandler: unrevokeCertificate(): begins.");
        if (serialno == null) {
            throw new EBaseException("CARemoteRequestHandler: unrevokeCertificate(): input parameter null.");
        }

        TPSSubsystem subsystem =
                (TPSSubsystem) CMS.getSubsystem(TPSSubsystem.ID);
        HttpConnector conn =
                (HttpConnector) subsystem.getConnectionManager().getConnector(connid);
        CMS.debug("CARemoteRequestHandler: unrevokeCertificate(): sending request to CA");
        HttpResponse resp =
                conn.send("unrevoke",
                        IRemoteRequest.CA_UNREVOKE_SERIAL + "=" + serialno.toString());
        String content = resp.getContent();

        CMS.debug("CARemoteRequestHandler: unrevokeCertificate(): got content = " + content);
        if (content != null && !content.equals("")) {
            Hashtable<String, Object> response =
                    parseResponse(content);

            /**
             * When a value is not found in response, keep going so we know
             * what else is missing
             */
            Integer ist = new Integer(IRemoteRequest.RESPONSE_STATUS_NOT_FOUND);
            String value = (String) response.get(IRemoteRequest.RESPONSE_STATUS);

            CMS.debug("CARemoteRequestHandler: unrevokeCertificate(): got status = " + value);
            ist = Integer.parseInt(value);
            if (ist != 0) {
                CMS.debug("CARemoteRequestHandler: unrevokeCertificate(): status not 0, getting error string... ");
                value = (String) response.get(IRemoteRequest.RESPONSE_ERROR_STRING);
                if (value == null) {
                    CMS.debug("CARemoteRequestHandler: unrevokeCertificate(): response missing name-value pair for: " +
                            IRemoteRequest.RESPONSE_ERROR_STRING);
                } else {
                    CMS.debug("CARemoteRequestHandler: unrevokeCertificate(): got IRemoteRequest.RESPONSE_ERROR_STRING = "
                            + value);
                    response.put(IRemoteRequest.RESPONSE_ERROR_STRING, value);
                }
            }
            response.put(IRemoteRequest.RESPONSE_STATUS, ist);

            CMS.debug("CARemoteRequestHandler: unrevokeCertificate(): ends.");
            return new CARevokeCertResponse(response);
        } else {
            CMS.debug("CARemoteRequestHandler: unrevokeCertificate(): no response content.");
            throw new EBaseException("CARemoteRequestHandler: unrevokeCertificate(): no response content.");
        }
    }

    /**
     * revokeFromOtherCA searches through all defined ca entries
     * to find the cert's signing ca for revocation / unrevocation.
     * It is called from revokeCertificate() when the cert's
     * AKI does not match that of the current signing ca.
     *
     * @param revoke true to revoke; false to unrevoke
     * @param cert cert to (un)revoke
     * @param serialno parameter for the (Un)RevokeCertificate() functions
     * @param reason RevocationReason for the base revokeCertificate() function
     */
    private CARevokeCertResponse revokeFromOtherCA(
            boolean revoke, // true==revoke; false==unrevoke
            X509CertImpl cert,
            RevocationReason reason)
            throws EBaseException {

        CMS.debug("CARemoteRequestHandler: revokeFromOtherCA: begins");
        if (cert == null) {
            throw new EBaseException("CARemoteRequestHandler: revokeFromOtherCA(): input parameter cert null.");
        }

        TPSSubsystem subsystem =
                (TPSSubsystem) CMS.getSubsystem(TPSSubsystem.ID);
        List<String> caList =
                subsystem.getConnectionManager().getCAList();

        Exception exception = null;
        String certAkiString = null;
        try {
            certAkiString = getCertAkiString(cert);
        } catch (Exception e) {
            exception = e;
        }

        for (String ca : caList) {
            try {
                String caSkiString = getCaSki(ca);
                if (certAkiString.equals(caSkiString)) {
                    CMS.debug("CARemoteRequestHandler: revokeFromOtherCA() cert AKI and caCert SKI matched");
                    if (revoke) {
                        return revokeCertificate(cert.getSerialNumber(), reason);
                    } else {
                        return unrevokeCertificate(cert.getSerialNumber());
                    }
                } else { // not a match then iterate to next ca in list
                    CMS.debug("CARemoteRequestHandler: revokeFromOtherCA() cert AKI and caCert SKI not matched");
                }
            } catch (Exception e) {
                // any issue then iterate to next ca in list
                CMS.debug("CARemoteRequestHandler: revokeFromOtherCA() issue found, iterate to next ca in list. Exception:"
                        + e);
                exception = e;
            }
        }
        if (exception == null) {
            throw new EBaseException("revokeFromOtherCA: signing ca not found");
        } else {
            throw new EBaseException(exception.toString());
        }
    }

    /**
     * getCaSki returns the CA's Subject Key Identifier (ski)
     * associated with the connector id.
     * If the ca's ski has not been calculated, it will do so and
     * save to the connector's caSKI config entry
     *
     * @param conn connector id
     * @returns ca's ski associated with conn
     */
    private String getCaSki(String conn)
            throws EBaseException, IOException {

        String caSkiString = null;
        if (conn == null) {
            throw new EBaseException("CARemoteRequestHandler: getCaSki(): input parameter conn null.");
        }

        IConfigStore conf = CMS.getConfigStore();

        /*
         * first, see if ca Subject Key Identifier (SKI) is in
         * config store. If not, put it in, so we don't have to
         * calculate that every time.
         */
        String caSKI = null;
        try {
            String configName = "tps.connector." + conn + ".caSKI";
            CMS.debug("CARemoteRequestHandler: getCaSki() retriving configName=" + configName);
            return conf.getString(configName);
        } catch (EPropertyNotFound e) {
            // caSKI not yet calculated; proceed to calculate
            CMS.debug("CARemoteRequestHandler: getCaSki() caSKI not yet calculated:" + e);
        } catch (EBaseException e) {
            throw e;
        }

        try {
            String caNickname =
                    conf.getString("tps.connector." + conn + ".caNickname");
            CMS.debug("CARemoteRequestHandler: getCaSki() Calculating caSKI...searching for ca cert in nss db:"
                    + caNickname);
            CryptoManager cm = CryptoManager.getInstance();
            try {
                X509Certificate c = cm.findCertByNickname(caNickname);
                X509CertImpl caCert = new X509CertImpl(c.getEncoded());
                // now retrieve caSKI and store in config
                caSkiString = getCertSkiString(caCert);
                CMS.debug("CARemoteRequestHandler: getCaSki() caSKI calculated. Saving it.");
                conf.putString("tps.connector." + conn + ".caSKI", caSkiString);
                conf.commit(false);
            } catch (IOException e) {
                throw e;
            } catch (Exception et) {
                /* ca cert not found in nss db; no match needed */
                CMS.debug("CARemoteRequestHandler: getCaSki() caSKI calculation failure." + et);
                throw new EBaseException("CARemoteRequestHandler: getCaSki(): skip match.");
            }
        } catch (EBaseException e) {
            /*
             *  if it gets here, that means config is missing both:
             *  1. tps.connector.ca<n>.caSKI
             *  2. tps.connector.ca<n>.caNickname
             *  now assume default of just using the issuing ca and
             *  no search performed
             */
            CMS.debug("CARemoteRequestHandler: getCaSki() caSKI calculation failure." + e);
            throw e;
        } catch (NotInitializedException e) {
            CMS.debug("CARemoteRequestHandler: getCaSki() caSKI calculation failure." + e);
            throw new EBaseException("CARemoteRequestHandler: getCaSki(): skip match.:" + e);
        }

        return caSkiString;
    }

    private String getCertAkiString(X509CertImpl cert)
            throws EBaseException, IOException {
        if (cert == null) {
            throw new EBaseException("CARemoteRequestHandler: getCertAkiString(): input parameter cert null.");
        }
        AuthorityKeyIdentifierExtension certAKI =
                (AuthorityKeyIdentifierExtension)
                cert.getExtension(PKIXExtensions.AuthorityKey_Id.toString());
        KeyIdentifier kid =
                (KeyIdentifier) certAKI.get(AuthorityKeyIdentifierExtension.KEY_ID);
        return (CMS.BtoA(kid.getIdentifier()).trim());
    }

    private String getCertSkiString(X509CertImpl cert)
            throws EBaseException, IOException {
        if (cert == null) {
            throw new EBaseException("CARemoteRequestHandler: getCertSkiString(): input parameter cert null.");
        }
        SubjectKeyIdentifierExtension certSKI =
                (SubjectKeyIdentifierExtension)
                cert.getExtension(PKIXExtensions.SubjectKey_Id.toString());
        KeyIdentifier kid =
                (KeyIdentifier) certSKI.get(SubjectKeyIdentifierExtension.KEY_ID);
        return (CMS.BtoA(kid.getIdentifier()).trim());
    }

    /**
     * revokeCertificate() supports revocation routing by providing
     * CA discovery. When needed, it searchs through all listed ca
     * entries to find the cert's signing ca for revocation.
     *
     * Note: in the configuration, the ca signing cert of each ca
     * id must be imported into the db and have its nickname present.
     * e.g. tps.connector.ca1.caNickname=CA1nickname
     *
     * See design:
     * http://pki.fedoraproject.org/wiki/TPS_-_Revocation_Routing
     *
     * @param revoke true to revoke; false to unrevoke
     * @param serialno serial number for the (Un)RevokeCertificate() functions
     * @param reason RevocationReason for the base revokeCertificate() function
     */
    public CARevokeCertResponse revokeCertificate(
            boolean revoke, // true==revoke; false==unrevoke
            X509CertImpl cert,
            RevocationReason reason)
            throws EBaseException {

        CMS.debug("CARemoteRequestHandler: revokeCertificate() begins with CA discovery");
        if (cert == null) {
            throw new EBaseException("CARemoteRequestHandler: revokeCertificate(): input parameter cert null.");
        }
        if (revoke == true && reason == null) {
            throw new EBaseException("CARemoteRequestHandler: revokeCertificate(): input parameter reason null.");
        }

        boolean skipMatch = false;

        String caSkiString = null;
        String certAkiString = null;

        try {
            caSkiString = getCaSki(connid);
            certAkiString = getCertAkiString(cert);
        } catch (Exception e) {
            CMS.debug("CARemoteRequestHandler: revokeCertificate() exception:" + e);
            skipMatch = true;
        }
        if (!skipMatch) {
            /* now compare cert's AKI to the ca's SKI
             *   if matched, continue,
             *   if not, search in the ca list
             */
            CMS.debug("CARemoteRequestHandler: revokeCertificate() cert AKI and caCert SKI matching begins");
            if (certAkiString.equals(caSkiString)) {
                CMS.debug("CARemoteRequestHandler: revokeCertificate() cert AKI and caCert SKI matched");
                if (revoke) {
                    return revokeCertificate(cert.getSerialNumber(), reason);
                } else {
                    return unrevokeCertificate(cert.getSerialNumber());
                }
            } else {
                CMS.debug("CARemoteRequestHandler: revokeCertificate() cert AKI and caCert SKI of the designated issuing ca do not match...calling revokeFromOtherCA to search for another ca");
                return revokeFromOtherCA(revoke, cert, reason);
            }
        } else {
            if (revoke) {
                return revokeCertificate(cert.getSerialNumber(), reason);
            } else {
                return unrevokeCertificate(cert.getSerialNumber());
            }
        }
    }
}
