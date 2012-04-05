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
package com.netscape.cmsutil.ocsp;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.mozilla.jss.asn1.ANY;
import org.mozilla.jss.asn1.ASN1Template;
import org.mozilla.jss.asn1.ASN1Value;
import org.mozilla.jss.asn1.EXPLICIT;
import org.mozilla.jss.asn1.GeneralizedTime;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.Tag;
import org.mozilla.jss.pkix.cert.Extension;

/**
 * RFC 2560:
 *
 * <pre>
 * SingleResponse ::= SEQUENCE {
 * certID                       CertID,
 * certStatus                   CertStatus,
 * thisUpdate                   GeneralizedTime,
 * nextUpdate           [0]     EXPLICIT GeneralizedTime OPTIONAL,
 * singleExtensions     [1]     EXPLICIT Extensions OPTIONAL }
 * </pre>
 *
 * @version $Revision$ $Date$
 */
public class SingleResponse implements ASN1Value {
    private CertID mCID = null;
    private CertStatus mStatus = null;
    private GeneralizedTime mThisUpdate = null;
    private GeneralizedTime mNextUpdate = null;

    private static final Tag TAG = SEQUENCE.TAG;

    public SingleResponse(CertID cid, CertStatus s,
            GeneralizedTime thisUpdate, GeneralizedTime nextUpdate) {
        mCID = cid;
        mStatus = s;
        mThisUpdate = thisUpdate;
        mNextUpdate = nextUpdate;
    }

    public CertID getCertID() {
        return mCID;
    }

    public Tag getTag() {
        return null;
    }

    public void encode(Tag t, OutputStream os) throws IOException {
        SEQUENCE seq = new SEQUENCE();
        seq.addElement(mCID);
        seq.addElement(mStatus);
        seq.addElement(mThisUpdate);
        if (mNextUpdate != null) {
            seq.addElement(new EXPLICIT(Tag.get(0), mNextUpdate));
        }
        if (t == null) {
            seq.encode(os);
        } else {
            seq.encode(t, os);
        }
    }

    public void encode(OutputStream os) throws IOException {
        encode(null, os);
    }

    public CertStatus getCertStatus() {
        return mStatus;
    }

    public GeneralizedTime getThisUpdate() {
        return mThisUpdate;
    }

    public GeneralizedTime getNextUpdate() {
        return mNextUpdate;
    }

    public int getExtensionCount() {
        return 0;
    }

    public Extension getExtensionAt(int pos) {
        return null;
    }

    private static final Template templateInstance = new Template();

    public static Template getTemplate() {
        return templateInstance;
    }

    /**
     * A Template for decoding <code>ResponseBytes</code>.
     */
    public static class Template implements ASN1Template {

        private SEQUENCE.Template seqt;

        public Template() {
            seqt = new SEQUENCE.Template();
            seqt.addElement(new CertID.Template());
            seqt.addElement(new ANY.Template());
            seqt.addElement(new GeneralizedTime.Template());
            seqt.addOptionalElement(new EXPLICIT.Template(
                        new Tag(0), new GeneralizedTime.Template()));
            seqt.addOptionalElement(new EXPLICIT.Template(new Tag(1),
                        new SEQUENCE.OF_Template(new Extension.Template())));

        }

        public boolean tagMatch(Tag tag) {
            return TAG.equals(tag);
        }

        public ASN1Value decode(InputStream istream)
                        throws InvalidBERException, IOException {
            return decode(TAG, istream);
        }

        public ASN1Value decode(Tag implicitTag, InputStream istream)
                        throws InvalidBERException, IOException {
            SEQUENCE seq = (SEQUENCE) seqt.decode(implicitTag,
                    istream);

            CertID cid = (CertID) seq.elementAt(0);
            CertStatus status = null;
            ANY e_status = (ANY) seq.elementAt(1);
            if (e_status.getTag().getNum() == 0) {
                status = (GoodInfo)
                                        GoodInfo.getTemplate().decode(
                                                e_status.getTag(),
                                                new ByteArrayInputStream(e_status.getEncoded()));
                // good
            } else if (e_status.getTag().getNum() == 1) {
                // revoked
                status = (RevokedInfo)
                                        RevokedInfo.getTemplate().decode(
                                                e_status.getTag(),
                                                new ByteArrayInputStream(e_status.getEncoded()));
            } else if (e_status.getTag().getNum() == 2) {
                // unknown
                status = (UnknownInfo)
                                        UnknownInfo.getTemplate().decode(
                                                e_status.getTag(),
                                                new ByteArrayInputStream(e_status.getEncoded()));
            }
            GeneralizedTime thisUpdate = (GeneralizedTime)
                    seq.elementAt(2);
            GeneralizedTime nextUpdate = null;

            return new SingleResponse(cid, status, thisUpdate,
                    nextUpdate);

        }
    }
}
