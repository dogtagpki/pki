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

public class CRMFUtil {

    public final static Logger logger = LoggerFactory.getLogger(CRMFUtil.class);

    public static SEQUENCE parseCRMFMsgs(byte[] request) throws IOException, InvalidBERException {

        if (request == null) {
            throw new IOException("Missing CRMF request");
        }

        ByteArrayInputStream crmfBlobIn = new ByteArrayInputStream(request);
        return (SEQUENCE) new SEQUENCE.OF_Template(new CertReqMsg.Template()).decode(crmfBlobIn);
    }
}
