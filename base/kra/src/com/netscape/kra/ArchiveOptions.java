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
package com.netscape.kra;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import org.mozilla.jss.asn1.ANY;
import org.mozilla.jss.asn1.BIT_STRING;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.SET;
import org.mozilla.jss.pkix.cms.EncryptedContentInfo;
import org.mozilla.jss.pkix.cms.EnvelopedData;
import org.mozilla.jss.pkix.cms.RecipientInfo;
import org.mozilla.jss.pkix.crmf.EncryptedKey;
import org.mozilla.jss.pkix.crmf.EncryptedValue;
import org.mozilla.jss.pkix.crmf.PKIArchiveOptions;
import org.mozilla.jss.pkix.primitive.AlgorithmIdentifier;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;

class ArchiveOptions {
    private String mSymmAlgOID = null;
    private byte mSymmAlgParams[] = null;
    private byte mEncSymmKey[] = null;
    private byte mEncValue[] = null;

    public ArchiveOptions(PKIArchiveOptions opts) throws EBaseException {
        try {
            EncryptedKey key = opts.getEncryptedKey();
            ANY enveloped_val = null;
            EncryptedValue val = null;
            AlgorithmIdentifier symmAlg = null;

            if (key.getType() == org.mozilla.jss.pkix.crmf.EncryptedKey.ENVELOPED_DATA) {
                CMS.debug("EnrollService: ArchiveOptions() EncryptedKey type= ENVELOPED_DATA");
                // this is the new RFC4211 EncryptedKey that should
                // have EnvelopedData to replace the deprecated EncryptedValue
                enveloped_val = key.getEnvelopedData();
                byte[] env_b = enveloped_val.getEncoded();
                EnvelopedData.Template env_template = new EnvelopedData.Template();
                EnvelopedData env_data =
                        (EnvelopedData) env_template.decode(new ByteArrayInputStream(env_b));
                EncryptedContentInfo eCI = env_data.getEncryptedContentInfo();
                symmAlg = eCI.getContentEncryptionAlgorithm();
                mSymmAlgOID = symmAlg.getOID().toString();
                mSymmAlgParams =
                        ((OCTET_STRING) ((ANY) symmAlg.getParameters()).decodeWith(OCTET_STRING.getTemplate()))
                                .toByteArray();

                SET recipients = env_data.getRecipientInfos();
                if (recipients.size() <= 0) {
                    CMS.debug("EnrollService: ArchiveOptions() - missing recipient information ");
                    throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ATTRIBUTE",
                            "[PKIArchiveOptions] missing recipient information "));
                }
                //check recpient - later
                //we only handle one recipient here anyways.  so, either the key
                //can be decrypted or it can't. No risk here.
                RecipientInfo ri = (RecipientInfo) recipients.elementAt(0);
                OCTET_STRING key_o = ri.getEncryptedKey();
                mEncSymmKey = key_o.toByteArray();

                OCTET_STRING oString = eCI.getEncryptedContent();
                BIT_STRING encVal = new BIT_STRING(oString.toByteArray(), 0);
                mEncValue = encVal.getBits();
                CMS.debug("EnrollService: ArchiveOptions() EncryptedKey type= ENVELOPED_DATA done");
            } else if (key.getType() == org.mozilla.jss.pkix.crmf.EncryptedKey.ENCRYPTED_VALUE) {
                CMS.debug("EnrollService: ArchiveOptions() EncryptedKey type= ENCRYPTED_VALUE");
                // this is deprecated: EncryptedValue
                val = key.getEncryptedValue();
                symmAlg = val.getSymmAlg();
                mSymmAlgOID = symmAlg.getOID().toString();
                mSymmAlgParams =
                        ((OCTET_STRING) ((ANY) symmAlg.getParameters()).decodeWith(OCTET_STRING.getTemplate()))
                                .toByteArray();
                BIT_STRING encSymmKey = val.getEncSymmKey();

                mEncSymmKey = encSymmKey.getBits();
                BIT_STRING encVal = val.getEncValue();

                mEncValue = encVal.getBits();
                CMS.debug("EnrollService: ArchiveOptions() EncryptedKey type= ENCRYPTED_VALUE done");
            } else {
                CMS.debug("EnrollService: ArchiveOptions() invalid EncryptedKey type");
                throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ATTRIBUTE", "[PKIArchiveOptions] type "
                        + key.getType()));
            }

        } catch (InvalidBERException e) {
            CMS.debug("EnrollService: ArchiveOptions(): " + e.toString());
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ATTRIBUTE",
                    "[PKIArchiveOptions]" + e.toString()));
        } catch (IOException e) {
            CMS.debug("EnrollService: ArchiveOptions(): " + e.toString());
            throw new EBaseException("ArchiveOptions() exception caught: " +
                    e.toString());
        } catch (Exception e) {
            CMS.debug("EnrollService: ArchiveOptions(): " + e.toString());
            throw new EBaseException("ArchiveOptions() exception caught: " +
                    e.toString());
        }

    }

    static public ArchiveOptions toArchiveOptions(byte options[]) throws
                                      EBaseException {
        ByteArrayInputStream bis = new ByteArrayInputStream(options);
        PKIArchiveOptions archOpts = null;

        try {
            archOpts = (PKIArchiveOptions)
                    (new PKIArchiveOptions.Template()).decode(bis);
        } catch (Exception e) {
            throw new EBaseException("Failed to decode input PKIArchiveOptions.");
        }

        return new ArchiveOptions(archOpts);

    }

    public String getSymmAlgOID() {
        return mSymmAlgOID;
    }

    public byte[] getSymmAlgParams() {
        return mSymmAlgParams;
    }

    public byte[] getEncSymmKey() {
        return mEncSymmKey;
    }

    public byte[] getEncValue() {
        return mEncValue;
    }
}
