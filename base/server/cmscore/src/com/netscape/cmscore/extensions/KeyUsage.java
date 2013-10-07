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
package com.netscape.cmscore.extensions;

import java.io.IOException;

import netscape.security.util.ObjectIdentifier;
import netscape.security.x509.Extension;
import netscape.security.x509.KeyUsageExtension;
import netscape.security.x509.PKIXExtensions;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.extensions.EExtensionsException;
import com.netscape.certsrv.extensions.ICMSExtension;
import com.netscape.cmscore.util.Debug;

public class KeyUsage implements ICMSExtension {
    private final static String NAME = "KeyUsageExtension";
    private final static ObjectIdentifier OID = PKIXExtensions.KeyUsage_Id;

    @SuppressWarnings("unused")
    private IConfigStore mConfig;
    private boolean mSetDefault = false;

    public KeyUsage(boolean setDefault) {
        mSetDefault = setDefault;
    }

    public void init(ISubsystem owner, IConfigStore config)
            throws EBaseException {
        // nothing to do here.
        mConfig = config;
    }

    public String getName() {
        return NAME;
    }

    public ObjectIdentifier getOID() {
        return OID;
    }

    protected static final boolean[] DEF_BITS =
            new boolean[KeyUsageExtension.NBITS];

    static {
        // set default bits used when request missing key usage info.
        DEF_BITS[KeyUsageExtension.DIGITAL_SIGNATURE_BIT] = true;
        DEF_BITS[KeyUsageExtension.NON_REPUDIATION_BIT] = false;
        DEF_BITS[KeyUsageExtension.KEY_ENCIPHERMENT_BIT] = true;
        DEF_BITS[KeyUsageExtension.DATA_ENCIPHERMENT_BIT] = true;
        DEF_BITS[KeyUsageExtension.KEY_AGREEMENT_BIT] = false;
        DEF_BITS[KeyUsageExtension.KEY_CERTSIGN_BIT] = false;
        DEF_BITS[KeyUsageExtension.CRL_SIGN_BIT] = false;
        DEF_BITS[KeyUsageExtension.ENCIPHER_ONLY_BIT] = false;
        DEF_BITS[KeyUsageExtension.DECIPHER_ONLY_BIT] = false;
    }

    private static boolean getBoolean(Object value) {
        String val = (String) value;

        if (val != null &&
                (val.equalsIgnoreCase("true") || val.equalsIgnoreCase("on")))
            return true;
        else
            return false;
    }

    public Extension getExtension(IArgBlock args) throws EBaseException {
        boolean[] bits = new boolean[KeyUsageExtension.NBITS];
        Object[] values = new Object[KeyUsageExtension.NBITS];
        int bit;

        // check if no bits are set. If not set default bits.
        bit = KeyUsageExtension.DIGITAL_SIGNATURE_BIT;
        values[bit] = args.get(KeyUsageExtension.names[bit]);
        bit = KeyUsageExtension.NON_REPUDIATION_BIT;
        values[bit] = args.get(KeyUsageExtension.names[bit]);
        bit = KeyUsageExtension.KEY_ENCIPHERMENT_BIT;
        values[bit] = args.get(KeyUsageExtension.names[bit]);
        bit = KeyUsageExtension.DATA_ENCIPHERMENT_BIT;
        values[bit] = args.get(KeyUsageExtension.names[bit]);
        bit = KeyUsageExtension.KEY_AGREEMENT_BIT;
        values[bit] = args.get(KeyUsageExtension.names[bit]);
        bit = KeyUsageExtension.KEY_CERTSIGN_BIT;
        values[bit] = args.get(KeyUsageExtension.names[bit]);
        bit = KeyUsageExtension.CRL_SIGN_BIT;
        values[bit] = args.get(KeyUsageExtension.names[bit]);
        bit = KeyUsageExtension.ENCIPHER_ONLY_BIT;
        values[bit] = args.get(KeyUsageExtension.names[bit]);
        bit = KeyUsageExtension.DECIPHER_ONLY_BIT;
        values[bit] = args.get(KeyUsageExtension.names[bit]);

        // if nothing is set, make one with default set of bits.
        int i;

        for (i = 0; i < KeyUsageExtension.NBITS; i++) {
            if (values[i] != null && (values[i] instanceof String))
                break;
        }
        if (i == KeyUsageExtension.NBITS && mSetDefault) {
            // no key usage extension parameters are requested. set default.
            CMS.debug(
                    "No Key usage bits requested. Setting default.");
            bits = DEF_BITS;
        } else {
            bit = KeyUsageExtension.DIGITAL_SIGNATURE_BIT;
            bits[bit] = getBoolean(values[bit]);
            if (Debug.ON)
                Debug.trace("Requested key usage bit " + bit + " " + bits[bit]);
            bit = KeyUsageExtension.NON_REPUDIATION_BIT;
            bits[bit] = getBoolean(values[bit]);
            if (Debug.ON)
                Debug.trace("Requested key usage bit " + bit + " " + bits[bit]);
            bit = KeyUsageExtension.KEY_ENCIPHERMENT_BIT;
            bits[bit] = getBoolean(values[bit]);
            if (Debug.ON)
                Debug.trace("Requested key usage bit " + bit + " " + bits[bit]);
            bit = KeyUsageExtension.DATA_ENCIPHERMENT_BIT;
            bits[bit] = getBoolean(values[bit]);
            if (Debug.ON)
                Debug.trace("Requested key usage bit " + bit + " " + bits[bit]);
            bit = KeyUsageExtension.KEY_AGREEMENT_BIT;
            bits[bit] = getBoolean(values[bit]);
            if (Debug.ON)
                Debug.trace("Requested key usage bit " + bit + " " + bits[bit]);
            bit = KeyUsageExtension.KEY_CERTSIGN_BIT;
            bits[bit] = getBoolean(values[bit]);
            if (Debug.ON)
                Debug.trace("Requested key usage bit " + bit + " " + bits[bit]);
            bit = KeyUsageExtension.CRL_SIGN_BIT;
            bits[bit] = getBoolean(values[bit]);
            if (Debug.ON)
                Debug.trace("Requested key usage bit " + bit + " " + bits[bit]);
            bit = KeyUsageExtension.ENCIPHER_ONLY_BIT;
            bits[bit] = getBoolean(values[bit]);
            if (Debug.ON)
                Debug.trace("Requested key usage bit " + bit + " " + bits[bit]);
            bit = KeyUsageExtension.DECIPHER_ONLY_BIT;
            bits[bit] = getBoolean(values[bit]);
            if (Debug.ON)
                Debug.trace("Requested key usage bit " + bit + " " + bits[bit]);
        }

        try {
            int j = 0;

            for (j = 0; j < bits.length; j++) {
                if (bits[j])
                    break;
            }
            if (j == bits.length) {
                if (!mSetDefault)
                    return null;
                else
                    bits = DEF_BITS;
            }
            return new KeyUsageExtension(bits);
        } catch (IOException e) {
            throw new EExtensionsException(
                    CMS.getUserMessage("CMS_EXTENSION_CREATING_EXT_ERROR", NAME));
        }
    }

    public IArgBlock getFormParams(Extension extension)
            throws EBaseException {
        KeyUsageExtension ext = null;

        if (!extension.getExtensionId().equals(PKIXExtensions.KeyUsage_Id)) {
            return null;
        }
        if (extension instanceof KeyUsageExtension) {
            ext = (KeyUsageExtension) extension;
        } else {
            try {
                byte[] value = extension.getExtensionValue();

                ext = new KeyUsageExtension(Boolean.valueOf(true), value);
            } catch (IOException e) {
                return null;
            }
        }

        IArgBlock params = CMS.createArgBlock();
        boolean[] bits = ext.getBits();

        params.set(KeyUsageExtension.DIGITAL_SIGNATURE,
                String.valueOf(bits[KeyUsageExtension.DIGITAL_SIGNATURE_BIT]));
        params.set(KeyUsageExtension.NON_REPUDIATION,
                String.valueOf(bits[KeyUsageExtension.NON_REPUDIATION_BIT]));
        params.set(KeyUsageExtension.KEY_ENCIPHERMENT,
                String.valueOf(bits[KeyUsageExtension.KEY_ENCIPHERMENT_BIT]));
        params.set(KeyUsageExtension.DATA_ENCIPHERMENT,
                String.valueOf(bits[KeyUsageExtension.DATA_ENCIPHERMENT_BIT]));
        params.set(KeyUsageExtension.KEY_AGREEMENT,
                String.valueOf(bits[KeyUsageExtension.KEY_AGREEMENT_BIT]));
        params.set(KeyUsageExtension.KEY_CERTSIGN,
                String.valueOf(bits[KeyUsageExtension.KEY_CERTSIGN_BIT]));
        params.set(KeyUsageExtension.CRL_SIGN,
                String.valueOf(bits[KeyUsageExtension.CRL_SIGN_BIT]));
        params.set(KeyUsageExtension.ENCIPHER_ONLY,
                String.valueOf(bits[KeyUsageExtension.ENCIPHER_ONLY_BIT]));
        params.set(KeyUsageExtension.DECIPHER_ONLY,
                String.valueOf(bits[KeyUsageExtension.DECIPHER_ONLY_BIT]));
        return params;
    }

}
