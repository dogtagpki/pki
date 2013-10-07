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
package com.netscape.cmscore.cert;

import java.util.Enumeration;
import java.util.Hashtable;
import java.util.StringTokenizer;

import netscape.security.util.DerValue;
import netscape.security.util.ObjectIdentifier;
import netscape.security.x509.AVAValueConverter;
import netscape.security.x509.DirStrConverter;
import netscape.security.x509.X500NameAttrMap;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.cmscore.util.Debug;

/**
 * Subsystem for configuring X500Name related things.
 * It is used for the following.
 * <ul>
 * <li>Add X500Name (string to oid) maps for attributes that are not supported by default.
 * <li>Specify an order for encoding Directory Strings other than the default.
 * </ul>
 *
 * @author lhsiao
 * @version $Revision$
 */
public class X500NameSubsystem implements ISubsystem {

    private IConfigStore mConfig = null;
    public static final String ID = "X500Name";
    private String mId = ID;

    private static final String PROP_DIR_STR_ENCODING_ORDER = "directoryStringEncodingOrder";

    private static final String PROP_ATTR = "attr";
    private static final String PROP_OID = "oid";
    private static final String PROP_CLASS = "class";

    private X500NameSubsystem() {
    }

    /**
     * Retrieves subsystem identifier.
     */
    public String getId() {
        return mId;
    }

    public void setId(String id) throws EBaseException {
        mId = id;
    }

    // singleton enforcement

    private static X500NameSubsystem mInstance = new X500NameSubsystem();

    public static X500NameSubsystem getInstance() {
        return mInstance;
    }

    /**
     * Initializes this subsystem with the given configuration store.
     * All paramters are optional.
     * <ul>
     * <li>Change encoding order of Directory Strings:
     *
     * <pre>
     * X500Name.directoryStringEncodingOrder=order seperated by commas
     * For example: Printable,BMPString,UniversalString.
     * </pre>
     *
     * Possible values are:
     * <ul>
     * <li>Printable
     * <li>IA5String
     * <li>UniversalString
     * <li>BMPString
     * <li>UTF8String
     * </ul>
     * <p>
     * <li>Add X500Name attributes:
     *
     * <pre>
     * X500Name.attr.attribute-name.oid=n.n.n.n
     * X500Name.attr.attribute-name.class=value converter class
     * </pre>
     *
     * The value converter class converts a string to a ASN.1 value. It must implement
     * netscape.security.x509.AVAValueConverter interface. Converter classes provided in CMS are:
     *
     * <pre>
     *     netscape.security.x509.PrintableConverter -
     * 		Converts to a Printable String value. String must have only
     * 		printable characters.
     *     netscape.security.x509.IA5StringConverter -
     * 		Converts to a IA5String value. String must have only IA5String
     * 		characters.
     *     netscape.security.x509.DirStrConverter -
     * 		Converts to a Directory (v3) String. String is expected to
     * 		be in Directory String format according to rfc2253.
     *     netscape.security.x509.GenericValueConverter -
     * 		Converts string character by character in the following order
     * 		from smaller character sets to broadest character set.
     * 			Printable, IA5String, BMPString, Universal String.
     * </pre>
     *
     * </ul>
     * <P>
     *
     * @param owner owner of this subsystem
     * @param config configuration store
     */
    public synchronized void init(ISubsystem owner, IConfigStore config)
            throws EBaseException {
        mLogger = CMS.getLogger();
        if (Debug.ON) {
            Debug.trace(ID + " started");
        }
        mConfig = config;

        // get order for encoding directory strings if any.
        setDirStrEncodingOrder();

        // load x500 name maps
        loadX500NameAttrMaps();
    }

    /**
     * Loads X500Name String to attribute maps.
     * Called from init.
     */
    private void loadX500NameAttrMaps()
            throws EBaseException {
        X500NameAttrMap globalMap = X500NameAttrMap.getDefault();
        IConfigStore attrSubStore = mConfig.getSubStore(PROP_ATTR);
        Enumeration<String> attrNames = attrSubStore.getSubStoreNames();

        while (attrNames.hasMoreElements()) {
            String name = attrNames.nextElement();
            IConfigStore substore = attrSubStore.getSubStore(name);
            String oidString = substore.getString(PROP_OID);
            ObjectIdentifier oid = CertUtils.checkOID(name, oidString);
            String className = substore.getString(PROP_CLASS);

            AVAValueConverter convClass = null;

            try {
                convClass = (AVAValueConverter)
                        Class.forName(className).newInstance();
            } catch (Exception e) {
                throw new EBaseException(
                        CMS.getUserMessage("CMS_BASE_LOAD_CLASS_FAILED", className, e.toString()));
            }
            globalMap.addNameOID(name, oid, convClass);
            if (Debug.ON) {
                Debug.trace(ID + ": Loaded " + name + " " + oid + " " + className);
            }
        }
    }

    /**
     * Set directory string encoding order.
     * Called from init().
     */
    private void setDirStrEncodingOrder()
            throws EBaseException {
        String order = mConfig.getString(PROP_DIR_STR_ENCODING_ORDER, null);

        if (order == null || order.length() == 0) // nothing.
            return;
        StringTokenizer toker = new StringTokenizer(order, ", \t");
        int numTokens = toker.countTokens();

        if (numTokens == 0) {
            String msg = "must be a list of DER tag names seperated by commas.";

            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_CERT_DIR_STRING", PROP_DIR_STR_ENCODING_ORDER));
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ATTR_VALUE",
                        PROP_DIR_STR_ENCODING_ORDER, msg));
        }

        byte[] tags = new byte[numTokens];

        for (int i = 0; toker.hasMoreTokens(); i++) {
            String nextTag = toker.nextToken();

            try {
                tags[i] = derStr2Tag(nextTag);
            } catch (IllegalArgumentException e) {
                String msg = "unknown DER tag '" + nextTag + "'.";

                log(ILogger.LL_FAILURE,
                        CMS.getLogMessage("CMSCORE_CERT_UNKNOWN_TAG", PROP_DIR_STR_ENCODING_ORDER, nextTag));
                throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ATTR_VALUE",
                            PROP_DIR_STR_ENCODING_ORDER, msg));
            }
        }

        DirStrConverter.setDefEncodingOrder(tags);
    }

    private static String PRINTABLESTRING = "PrintableString";
    private static String IA5STRING = "IA5String";
    private static String VISIBLESTRING = "VisibleString";
    private static String T61STRING = "T61String";
    private static String BMPSTRING = "BMPString";
    private static String UNIVERSALSTRING = "UniversalString";
    private static String UFT8STRING = "UTF8String";
    private static Hashtable<String, Byte> mDerStr2TagHash = new Hashtable<String, Byte>();

    static {
        mDerStr2TagHash.put(
                PRINTABLESTRING, Byte.valueOf(DerValue.tag_PrintableString));
        mDerStr2TagHash.put(
                IA5STRING, Byte.valueOf(DerValue.tag_IA5String));
        mDerStr2TagHash.put(
                VISIBLESTRING, Byte.valueOf(DerValue.tag_VisibleString));
        mDerStr2TagHash.put(
                T61STRING, Byte.valueOf(DerValue.tag_T61String));
        mDerStr2TagHash.put(
                BMPSTRING, Byte.valueOf(DerValue.tag_BMPString));
        mDerStr2TagHash.put(
                UNIVERSALSTRING, Byte.valueOf(DerValue.tag_UniversalString));
        mDerStr2TagHash.put(
                UFT8STRING, Byte.valueOf(DerValue.tag_UTF8String));
    }

    private byte derStr2Tag(String s) {
        if (s == null || s.length() == 0)
            throw new IllegalArgumentException();
        Byte tag = mDerStr2TagHash.get(s);

        if (tag == null)
            throw new IllegalArgumentException();
        return tag.byteValue();
    }

    public void startup() throws EBaseException {
    }

    /**
     * Stops this system.
     */
    public synchronized void shutdown() {
    }

    /*
     * Returns the root configuration storage of this system.
     * <P>
     *
     * @return configuration store of this subsystem
     */
    public IConfigStore getConfigStore() {
        return mConfig;
    }

    protected ILogger mLogger = null;

    protected synchronized void log(int level, String msg) {
        mLogger.log(ILogger.EV_SYSTEM,
                ILogger.S_ADMIN, level, msg);
    }

}
