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
package com.netscape.cmscore.crmf;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Vector;

import org.mozilla.jss.asn1.ASN1Util;
import org.mozilla.jss.asn1.ASN1Value;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.pkix.crmf.CertReqMsg;
import org.mozilla.jss.pkix.crmf.CertRequest;
import org.mozilla.jss.pkix.crmf.PKIArchiveOptions;
import org.mozilla.jss.pkix.primitive.AVA;

import com.netscape.certsrv.apps.CMS;

public class CRMFParser {

    private static final OBJECT_IDENTIFIER PKIARCHIVEOPTIONS_OID =
            new OBJECT_IDENTIFIER(new long[] { 1, 3, 6, 1, 5, 5, 7, 5, 1, 4 }
            );

    /**
     * Retrieves PKIArchiveOptions from CRMF request.
     *
     * @param request CRMF request
     * @return PKIArchiveOptions
     * @exception failed to extrace option
     */
    public static PKIArchiveOptionsContainer[]
            getPKIArchiveOptions(String crmfBlob) throws IOException {
        Vector<PKIArchiveOptionsContainer> options = new Vector<PKIArchiveOptionsContainer>();

        byte[] crmfBerBlob = null;

        crmfBerBlob = CMS.AtoB(crmfBlob);
        if (crmfBerBlob == null)
            throw new IOException("no CRMF data found");

        ByteArrayInputStream crmfBerBlobIn = new
                ByteArrayInputStream(crmfBerBlob);
        SEQUENCE crmfmsgs = null;

        try {
            crmfmsgs = (SEQUENCE) new
                    SEQUENCE.OF_Template(new
                            CertReqMsg.Template()).decode(
                            crmfBerBlobIn);
        } catch (IOException e) {
            throw new IOException("[crmf msgs]" + e.toString());
        } catch (InvalidBERException e) {
            throw new IOException("[crmf msgs]" + e.toString());
        }

        for (int z = 0; z < crmfmsgs.size(); z++) {
            CertReqMsg certReqMsg = (CertReqMsg)
                    crmfmsgs.elementAt(z);
            CertRequest certReq = certReqMsg.getCertReq();

            // try to locate PKIArchiveOption control
            AVA archAva = null;

            try {
                for (int i = 0; i < certReq.numControls(); i++) {
                    AVA ava = certReq.controlAt(i);
                    OBJECT_IDENTIFIER oid = ava.getOID();

                    if (oid.equals(PKIARCHIVEOPTIONS_OID)) {
                        archAva = ava;
                        break;
                    }
                }
            } catch (Exception e) {
                throw new IOException("no PKIArchiveOptions found " + e.toString());
            }
            if (archAva != null) {

                ASN1Value archVal = archAva.getValue();
                ByteArrayInputStream bis = new ByteArrayInputStream(ASN1Util.encode(archVal));
                PKIArchiveOptions archOpts = null;

                try {
                    archOpts = (PKIArchiveOptions)
                            (new PKIArchiveOptions.Template()).decode(bis);
                } catch (IOException e) {
                    throw new IOException("[PKIArchiveOptions]" + e.toString());
                } catch (InvalidBERException e) {
                    throw new IOException("[PKIArchiveOptions]" + e.toString());
                }
                options.addElement(new PKIArchiveOptionsContainer(archOpts, z));
            }
        }
        if (options.size() == 0) {
            throw new IOException("no PKIArchiveOptions found");
        } else {
            PKIArchiveOptionsContainer p[] = new PKIArchiveOptionsContainer[options.size()];

            options.copyInto(p);
            //  options.clear();
            return p;
        }
    }
}
