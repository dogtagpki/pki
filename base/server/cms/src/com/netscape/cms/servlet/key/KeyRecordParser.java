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
package com.netscape.cms.servlet.key;

import java.util.Date;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.base.IPrettyPrintFormat;
import com.netscape.certsrv.base.MetaInfo;
import com.netscape.certsrv.dbs.keydb.IKeyRecord;

/**
 * Output a 'pretty print' of a Key Archival record
 *
 * @version $Revision$, $Date$
 */
public class KeyRecordParser {

    public final static String OUT_STATE = "state";
    public final static String OUT_OWNER_NAME = "ownerName";
    public final static String OUT_SERIALNO = "serialNumber";
    public final static String OUT_SERIALNO_IN_HEX = "serialNumberInHex";
    public final static String OUT_KEY_ALGORITHM = "keyAlgorithm";
    public final static String OUT_PUBLIC_KEY = "publicKey";
    public final static String OUT_KEY_LEN = "keyLength";
    public final static String OUT_KEY_EC_CURVE = "EllipticCurve";
    public final static String OUT_ARCHIVED_BY = "archivedBy";
    public final static String OUT_ARCHIVED_ON = "archivedOn";
    public final static String OUT_RECOVERED_BY = "recoveredBy";
    public final static String OUT_RECOVERED_ON = "recoveredOn";

    /**
     * Fills key record into argument block.
     */
    public static void fillRecordIntoArg(IKeyRecord rec, IArgBlock rarg)
            throws EBaseException {
        if (rec == null)
            return;
        rarg.addStringValue(OUT_STATE,
                rec.getState().toString());
        rarg.addStringValue(OUT_OWNER_NAME,
                rec.getOwnerName());
        rarg.addBigIntegerValue(OUT_SERIALNO,
                rec.getSerialNumber(), 10);
        rarg.addBigIntegerValue(OUT_SERIALNO_IN_HEX,
                rec.getSerialNumber(), 16);
        rarg.addStringValue(OUT_KEY_ALGORITHM,
                rec.getAlgorithm());
        // Possible Enhancement: sun's BASE64Encode is not
        // fast. We may may to have our native implmenetation.
        IPrettyPrintFormat pp = CMS.getPrettyPrintFormat(":");

        rarg.addStringValue(OUT_PUBLIC_KEY,
                pp.toHexString(rec.getPublicKeyData(), 0, 20));
        Integer keySize = rec.getKeySize();

        if (keySize == null) {
            rarg.addIntegerValue(OUT_KEY_LEN, 512);
        } else {
            rarg.addIntegerValue(OUT_KEY_LEN, keySize.intValue());
        }

        // handles EC
        MetaInfo metaInfo = rec.getMetaInfo();
        if (metaInfo != null) {
            String curve = (String)metaInfo.get(OUT_KEY_EC_CURVE);
            if (curve != null) {
                rarg.addStringValue(OUT_KEY_EC_CURVE, curve);
            }
        }

        rarg.addStringValue(OUT_ARCHIVED_BY,
                rec.getArchivedBy());
        rarg.addLongValue(OUT_ARCHIVED_ON,
                rec.getCreateTime().getTime() / 1000);
        Date dateOfRevocation[] = rec.getDateOfRevocation();

        if (dateOfRevocation != null) {
            rarg.addStringValue(OUT_RECOVERED_BY,
                    "null");
            rarg.addStringValue(OUT_RECOVERED_ON,
                    "null");
        }
    }
}
