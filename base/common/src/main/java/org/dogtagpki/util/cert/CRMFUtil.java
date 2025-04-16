//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package org.dogtagpki.util.cert;

import java.io.ByteArrayInputStream;
import java.io.IOException;

import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.pkix.crmf.CertReqMsg;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.profile.EProfileException;

public class CRMFUtil {

    public final static Logger logger = LoggerFactory.getLogger(CRMFUtil.class);

    public static SEQUENCE parseCRMFMsgs(byte[] request) throws IOException, InvalidBERException {

        if (request == null) {
            throw new IOException("Missing CRMF request");
        }

        ByteArrayInputStream crmfBlobIn = new ByteArrayInputStream(request);
        return (SEQUENCE) new SEQUENCE.OF_Template(new CertReqMsg.Template()).decode(crmfBlobIn);
    }

    public static CertReqMsg[] parseCRMF(String request) throws Exception {

        if (request == null) {
            logger.error("CRMFUtil: Missing CRMF request");
            throw new EProfileException("Missing CRMF request");
        }

        byte[] data = CertUtil.parseCSR(request);

        try {
            ByteArrayInputStream crmfBlobIn = new ByteArrayInputStream(data);
            SEQUENCE crmfMsgs = (SEQUENCE) new SEQUENCE.OF_Template(
                    new CertReqMsg.Template()).decode(crmfBlobIn);

            int size = crmfMsgs.size();
            if (size <= 0) {
                return null;
            }

            CertReqMsg[] msgs = new CertReqMsg[crmfMsgs.size()];
            for (int i = 0; i < size; i++) {
                msgs[i] = (CertReqMsg) crmfMsgs.elementAt(i);
            }

            return msgs;

        } catch (Exception e) {
            logger.error("Unable to parse CRMF request: " + e.getMessage(), e);
            throw new EProfileException("Unable to parse CRMF request: " + e.getMessage(), e);
        }
    }
}
