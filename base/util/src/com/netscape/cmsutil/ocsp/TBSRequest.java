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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.mozilla.jss.asn1.ANY;
import org.mozilla.jss.asn1.ASN1Template;
import org.mozilla.jss.asn1.ASN1Value;
import org.mozilla.jss.asn1.EXPLICIT;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.InvalidBERException;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.asn1.Tag;
import org.mozilla.jss.pkix.cert.Extension;

/**
 * RFC 2560:
 *
 * <pre>
 * TBSRequest      ::=     SEQUENCE {
 *  version             [0] EXPLICIT Version DEFAULT v1,
 *  requestorName       [1] EXPLICIT GeneralName OPTIONAL,
 *  requestList             SEQUENCE OF Request,
 *  requestExtensions   [2] EXPLICIT Extensions OPTIONAL }
 * </pre>
 *
 * @version $Revision$ $Date$
 */

public class TBSRequest implements ASN1Value {
    ///////////////////////////////////////////////////////////////////////
    // members and member access
    ///////////////////////////////////////////////////////////////////////
    private static final INTEGER v1 = new INTEGER(0);
    private INTEGER version;
    private ANY requestorName;
    private SEQUENCE requestList;
    private SEQUENCE requestExtensions;

    public INTEGER getVersion() {
        return version;
    }

    public ANY getRequestorName() {
        return requestorName;
    }

    public int getRequestCount() {
        if (requestList == null) {
            return 0;
        } else {
            return requestList.size();
        }
    }

    public Request getRequestAt(int index) {
        return (Request) requestList.elementAt(index);
    }

    public int getExtensionsCount() {
        if (requestExtensions == null) {
            return 0;
        } else {
            return requestExtensions.size();
        }
    }

    public Extension getRequestExtensionAt(int index) {
        return (Extension) requestExtensions.elementAt(index);
    }

    ///////////////////////////////////////////////////////////////////////
    // constructors
    ///////////////////////////////////////////////////////////////////////

    public TBSRequest(INTEGER version, ANY requestorName,
            SEQUENCE requestList, SEQUENCE requestExtensions) {
        this.version = (version != null) ? version : v1;
        this.requestorName = requestorName;
        this.requestList = requestList;
        this.requestExtensions = requestExtensions;
    }

    ///////////////////////////////////////////////////////////////////////
    // encode / decode
    ///////////////////////////////////////////////////////////////////////
    public static final Tag TAG = SEQUENCE.TAG;

    public Tag getTag() {
        return TAG;
    }

    public void encode(OutputStream ostream)
            throws IOException {
        encode(TAG, ostream);
    }

    public void encode(Tag implicitTag, OutputStream ostream)
            throws IOException {
        SEQUENCE seq = new SEQUENCE();

        if (version != v1) {
            seq.addElement(new EXPLICIT(Tag.get(0), version));
        }

        if (requestorName != null) {
            seq.addElement(new EXPLICIT(Tag.get(1), requestorName));
        }

        seq.addElement(requestList);

        if (requestExtensions != null) {
            seq.addElement(new EXPLICIT(Tag.get(2), requestExtensions));
        }
        if (implicitTag == null) {
            seq.encode(ostream);
        } else {
            seq.encode(implicitTag, ostream);
        }
    }

    private static final Template templateInstance = new Template();

    public static Template getTemplate() {
        return templateInstance;
    }

    /**
     * A Template for decoding TBSRequest.
     */
    public static class Template implements ASN1Template {

        private SEQUENCE.Template seqt;

        public Template() {
            seqt = new SEQUENCE.Template();
            seqt.addElement(
                    new EXPLICIT.Template(
                            new Tag(0), new INTEGER.Template()),
                    new EXPLICIT(new Tag(0), new INTEGER(0))
                    );
            seqt.addOptionalElement(
                    new EXPLICIT.Template(
                            new Tag(1), new ANY.Template()));
            seqt.addElement(new SEQUENCE.OF_Template(new Request.Template()));
            seqt.addOptionalElement(new EXPLICIT.Template(new Tag(2),
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
            SEQUENCE seq = (SEQUENCE) seqt.decode(implicitTag, istream);

            INTEGER v = v1; //assume default version
            EXPLICIT e_ver = (EXPLICIT) seq.elementAt(0);
            if (e_ver != null) {
                v = (INTEGER) e_ver.getContent();
            }

            ANY requestorname = null;
            EXPLICIT e_requestorName = (EXPLICIT) seq.elementAt(1);
            if (e_requestorName != null) {
                requestorname = (ANY) e_requestorName.getContent();
            }

            //request sequence (element 2) done below

            EXPLICIT exts = (EXPLICIT) seq.elementAt(3);
            SEQUENCE exts_seq;
            if (exts != null) {
                exts_seq = (SEQUENCE) exts.getContent();
            } else {
                exts_seq = null;
            }

            return new TBSRequest(
                    v,
                    requestorname,
                    (SEQUENCE) seq.elementAt(2),
                    exts_seq);
        }
    }
}
