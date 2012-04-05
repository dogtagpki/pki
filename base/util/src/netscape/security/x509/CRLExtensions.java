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
package netscape.security.x509;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import netscape.security.util.DerInputStream;
import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;

/**
 * This class defines the CRL Extensions.
 *
 * @author Hemma Prafullchandra
 * @version 1.4
 */
public class CRLExtensions extends Vector<Extension> {

    /**
     *
     */
    private static final long serialVersionUID = 365767738692986418L;
    private Hashtable<String, Extension> map;

    // Parse the encoded extension
    private void parseExtension(Extension ext) throws X509ExtensionException {
        try {
            Class<?> extClass = OIDMap.getClass(ext.getExtensionId());
            if (extClass == null) { // Unsupported extension
                if (ext.isCritical()) {
                    throw new IOException("Unsupported CRITICAL extension: "
                                          + ext.getExtensionId());
                } else {
                    map.put(ext.getExtensionId().toString(), ext);
                    addElement(ext);
                    return;
                }
            }
            Class<?>[] params = { Boolean.class, Object.class };
            Constructor<?> cons = extClass.getConstructor(params);
            byte[] extData = ext.getExtensionValue();
            int extLen = extData.length;
            Object value = Array.newInstance(byte.class, extLen);

            for (int i = 0; i < extLen; i++) {
                Array.setByte(value, i, extData[i]);
            }
            Object[] passed = new Object[] { new Boolean(ext.isCritical()),
                                                        value };
            CertAttrSet crlExt = (CertAttrSet) cons.newInstance(passed);
            map.put(crlExt.getName(), (Extension) crlExt);
            addElement((Extension) crlExt);

        } catch (InvocationTargetException invk) {
            throw new X509ExtensionException(
                                 invk.getTargetException().getMessage());

        } catch (Exception e) {
            throw new X509ExtensionException(e.toString());
        }
    }

    /**
     * Default constructor.
     */
    public CRLExtensions() {
        map = new Hashtable<String, Extension>();
    }

    /**
     * Create the object, decoding the values from the passed DER stream.
     *
     * @param in the DerInputStream to read the Extension from.
     * @exception CRLException on decoding errors.
     * @exception X509ExtensionException on extension handling errors.
     */
    public CRLExtensions(DerInputStream in)
            throws CRLException, X509ExtensionException {

        map = new Hashtable<String, Extension>();
        try {
            DerValue[] exts = in.getSequence(5);

            for (int i = 0; i < exts.length; i++) {
                Extension ext = new Extension(exts[i]);
                parseExtension(ext);
            }
        } catch (IOException e) {
            throw new CRLException("Parsing error: " + e.toString());
        }
    }

    /**
     * Decode the extensions from the InputStream.
     *
     * @param in the InputStream to unmarshal the contents from.
     * @exception CRLException on decoding or validity errors.
     * @exception X509ExtensionException on extension handling errors.
     */
    public void decode(InputStream in)
            throws CRLException, X509ExtensionException {
        try {
            DerValue val = new DerValue(in);
            DerInputStream str = val.toDerInputStream();

            map = new Hashtable<String, Extension>();
            DerValue[] exts = str.getSequence(5);

            for (int i = 0; i < exts.length; i++) {
                Extension ext = new Extension(exts[i]);
                parseExtension(ext);
            }
        } catch (IOException e) {
            throw new CRLException("Parsing error: " + e.toString());
        }
    }

    /**
     * Encode the extensions in DER form to the stream.
     *
     * @param out the DerOutputStream to marshal the contents to.
     * @param isExplicit the tag indicating whether this is an entry
     *            extension or a CRL extension.
     * @exception CRLException on encoding errors.
     */
    public void encode(OutputStream out, boolean isExplicit)
            throws CRLException {
        try {
            // #381559
            if (size() == 0)
                return;
            DerOutputStream extOut = new DerOutputStream();
            for (int i = 0; i < size(); i++) {
                Object thisOne = elementAt(i);
                if (thisOne instanceof CertAttrSet)
                    ((CertAttrSet) thisOne).encode(extOut);
                else if (thisOne instanceof Extension)
                    ((Extension) thisOne).encode(extOut);
                else
                    throw new CRLException("Illegal extension object");
            }

            DerOutputStream seq = new DerOutputStream();
            seq.write(DerValue.tag_Sequence, extOut);

            DerOutputStream tmp = new DerOutputStream();
            if (isExplicit)
                tmp.write(DerValue.createTag(DerValue.TAG_CONTEXT,
                                             true, (byte) 0), seq);
            else
                tmp = seq;

            out.write(tmp.toByteArray());
        } catch (IOException e) {
            throw new CRLException("Encoding error: " + e.toString());
        } catch (CertificateException e) {
            throw new CRLException("Encoding error: " + e.toString());
        }
    }

    /**
     * Get the extension with this alias.
     *
     * @param alias the identifier string for the extension to retrieve.
     * @exception X509ExtensionException on extension handling errors.
     */
    public Extension get(String alias) throws X509ExtensionException {
        X509AttributeName attr = new X509AttributeName(alias);
        String name;
        String id = attr.getPrefix();
        if (id.equalsIgnoreCase(X509CertImpl.NAME)) { // fully qualified
            int index = alias.lastIndexOf(".");
            name = alias.substring(index + 1);
        } else
            name = alias;
        Extension ext = (Extension) map.get(name);
        if (ext == null)
            throw new X509ExtensionException("No extension found with name: "
                                             + alias);
        return ext;
    }

    /**
     * Set the extension value with this alias.
     *
     * @param alias the identifier string for the extension to set.
     * @param obj the Object to set the extension identified by the
     *            alias.
     * @exception IOException on errors.
     */
    public void set(String alias, Extension obj) throws IOException {
        map.put(alias, obj);
        addElement(obj);
    }

    /**
     * Return an enumeration of names of the extensions.
     *
     * @return an enumeration of the names of the extensions in this CRL.
     */
    public Enumeration<Extension> getElements() {
        return (map.elements());
    }
}
