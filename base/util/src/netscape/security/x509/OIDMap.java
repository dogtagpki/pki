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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Properties;

import netscape.security.util.ObjectIdentifier;

/**
 * This class defines the mapping from OID & name to classes and vice
 * versa. Used by CertificateExtensions & PKCS10 to get the java
 * classes associated with a particular OID/name.
 *
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 * @version 1.12
 */
public class OIDMap {

    /**
     * Location for where the OID/Classes maps are stored on
     * the local system.
     */
    public static final String EXTENSIONS_HOME =
            (System.getProperty("java.home") + File.separator + "lib"
                    + File.separator + "security" + File.separator + "cert"
            + File.separator);
    /**
     * File names for where OIDs and Classes are registered
     * for V3 extensions.
     */
    public static final String EXTENSIONS_OIDS = "x509extensions.oid";
    public static final String EXTENSIONS_CLASSES = "x509extensions.classes";

    // Make default names easier
    private static final String ROOT = X509CertImpl.NAME + "." +
                                 X509CertInfo.NAME + "." +
                                 X509CertInfo.EXTENSIONS;
    private static final String AUTH_KEY_IDENTIFIER = ROOT + "." +
                                          AuthorityKeyIdentifierExtension.NAME;
    private static final String SUB_KEY_IDENTIFIER = ROOT + "." +
                                          SubjectKeyIdentifierExtension.NAME;
    private static final String KEY_USAGE = ROOT + "." +
                                          KeyUsageExtension.NAME;
    private static final String PRIVATE_KEY_USAGE = ROOT + "." +
                                          PrivateKeyUsageExtension.NAME;
    private static final String POLICY_MAPPINGS = ROOT + "." +
                                          PolicyMappingsExtension.NAME;
    private static final String SUB_ALT_NAME = ROOT + "." +
                                          SubjectAlternativeNameExtension.NAME;
    private static final String ISSUER_ALT_NAME = ROOT + "." +
                                          IssuerAlternativeNameExtension.NAME;
    private static final String BASIC_CONSTRAINTS = ROOT + "." +
                                          BasicConstraintsExtension.NAME;
    private static final String NAME_CONSTRAINTS = ROOT + "." +
                                          NameConstraintsExtension.NAME;
    private static final String POLICY_CONSTRAINTS = ROOT + "." +
                                          PolicyConstraintsExtension.NAME;
    private static final String CERT_POLICIES = //ROOT + "." +
            CertificatePoliciesExtension.NAME;
    private static final String SUBJ_DIR_ATTR = //ROOT + "." +
            SubjectDirAttributesExtension.NAME;
    public static final String EXT_KEY_USAGE_NAME = "ExtendedKeyUsageExtension";
    public static final String EXT_INHIBIT_ANY_POLICY_NAME = "InhibitAnyPolicyExtension";
    private static final String EXT_KEY_USAGE = //ROOT + "." +
            EXT_KEY_USAGE_NAME;

    private static final String CRL_NUMBER = ROOT + "." +
                                          CRLNumberExtension.NAME;
    private static final String CRL_REASON = ROOT + "." +
                                          CRLReasonExtension.NAME;

    private static final Hashtable<ObjectIdentifier, String> oid2Name = new Hashtable<ObjectIdentifier, String>();
    private static final Hashtable<String, ObjectIdentifier> name2OID = new Hashtable<String, ObjectIdentifier>();
    private static final Hashtable<String, String> name2Class = new Hashtable<String, String>();

    // Initialize recognized extensions from EXTENSIONS_{OIDS/CLASSES} files
    static {
        loadNames();
        loadClasses();
    }

    // Load the default name to oid map (EXTENSIONS_OIDS)
    private static void loadNamesDefault(Properties props) {
        props.put(SUB_KEY_IDENTIFIER, "2.5.29.14");
        props.put(KEY_USAGE, "2.5.29.15");
        props.put(PRIVATE_KEY_USAGE, "2.5.29.16");
        props.put(SUB_ALT_NAME, "2.5.29.17");
        props.put(ISSUER_ALT_NAME, "2.5.29.18");
        props.put(BASIC_CONSTRAINTS, "2.5.29.19");
        props.put(CRL_NUMBER, "2.5.29.20");
        props.put(CRL_REASON, "2.5.29.21");
        props.put(NAME_CONSTRAINTS, "2.5.29.30");
        props.put(POLICY_MAPPINGS, "2.5.29.33");
        props.put(POLICY_CONSTRAINTS, "2.5.29.36");
        props.put(CERT_POLICIES, "2.5.29.32");
        props.put(AUTH_KEY_IDENTIFIER, "2.5.29.35");
        props.put(SUBJ_DIR_ATTR, "2.5.29.9");
        props.put(EXT_KEY_USAGE, "2.5.29.37");
    }

    // Load the default name to class map (EXTENSIONS_CLASSES)
    private static void loadClassDefault(Properties props) {
        props.put(AUTH_KEY_IDENTIFIER,
                   "netscape.security.x509.AuthorityKeyIdentifierExtension");
        props.put(SUB_KEY_IDENTIFIER,
                  "netscape.security.x509.SubjectKeyIdentifierExtension");
        props.put(KEY_USAGE,
                  "netscape.security.x509.KeyUsageExtension");
        props.put(PRIVATE_KEY_USAGE,
                  "netscape.security.x509.PrivateKeyUsageExtension");
        props.put(POLICY_MAPPINGS,
                  "netscape.security.x509.PolicyMappingsExtension");
        props.put(SUB_ALT_NAME,
                  "netscape.security.x509.SubjectAlternativeNameExtension");
        props.put(ISSUER_ALT_NAME,
                  "netscape.security.x509.IssuerAlternativeNameExtension");
        props.put(BASIC_CONSTRAINTS,
                  "netscape.security.x509.BasicConstraintsExtension");
        props.put(NAME_CONSTRAINTS,
                  "netscape.security.x509.NameConstraintsExtension");
        props.put(POLICY_CONSTRAINTS,
                  "netscape.security.x509.PolicyConstraintsExtension");
        props.put(CERT_POLICIES,
                  "netscape.security.x509.CertificatePoliciesExtension");
        props.put(SUBJ_DIR_ATTR,
                  "netscape.security.x509.SubjectDirAttributesExtension");
        props.put(EXT_KEY_USAGE,
                  "netscape.security.extensions.ExtendedKeyUsageExtension");
        props.put(CRL_NUMBER, "netscape.security.x509.CRLNumberExtension");
        props.put(CRL_REASON, "netscape.security.x509.CRLReasonExtension");
    }

    // Return the file along with location
    private static File certificatePropFile(String fileName) {
        return (new File(EXTENSIONS_HOME + fileName));
    }

    // Load the names to oid map
    private static void loadNames() {
        Properties props = new Properties();
        File namesMap = certificatePropFile(EXTENSIONS_OIDS);

        if (!namesMap.exists()) {
            loadNamesDefault(props);
        } else {
            try {
                FileInputStream fis = new FileInputStream(namesMap);
                props.load(fis);
                fis.close();
            } catch (IOException e) {
                loadNamesDefault(props);
            }
        }

        Iterator<String> names = props.stringPropertyNames().iterator();
        while (names.hasNext()) {
            String name = names.next();
            String oidName = props.getProperty(name);
            ObjectIdentifier oid = new ObjectIdentifier(oidName);

            name2OID.put(name, oid);
            oid2Name.put(oid, name);
        }
    }

    // Load the names to classes map
    private static void loadClasses() {
        Properties props = new Properties();
        File classMap = certificatePropFile(EXTENSIONS_CLASSES);

        if (!classMap.exists()) {
            loadClassDefault(props);
        } else {
            try {
                FileInputStream fis = new FileInputStream(classMap);
                props.load(fis);
            } catch (IOException e) {
                loadClassDefault(props);
            }
        }

        Iterator<String> names = props.stringPropertyNames().iterator();
        while (names.hasNext()) {
            String name = names.next();
            String className = props.getProperty(name);

            name2Class.put(name, className);
        }
    }

    /**
     * Add a name to lookup table.
     *
     * @param className the name of the fully qualified class implementing
     *            the asn object.
     * @param oid the string representation of the object identifier for
     *            the class.
     * @param name the name of the attribute.
     * @exception CertificateException on errors.
     */
    public static void addAttribute(String className, String oid, String name)
            throws CertificateException {
        ObjectIdentifier objId = new ObjectIdentifier(oid);
        if (oid2Name.get(objId) != null) {
            throw new CertificateException("Object identifier already exists.");
        }
        if (name2OID.get(name) != null) {
            throw new CertificateException("Name already exists.");
        }
        if (name2Class.get(className) != null) {
            throw new CertificateException("Class already exists.");
        }
        oid2Name.put(objId, name);
        name2OID.put(name, objId);
        name2Class.put(name, className);
    }

    /**
     * Return user friendly name associated with the OID.
     *
     * @param oid the name of the object identifier to be returned.
     * @return the user friendly name or null if no name
     *         is registered for this oid.
     */
    public static String getName(ObjectIdentifier oid) {
        return oid2Name.get(oid);
    }

    /**
     * Return Object identifier for user friendly name.
     *
     * @param name the user friendly name.
     * @return the Object Identifier or null if no oid
     *         is registered for this name.
     */
    public static ObjectIdentifier getOID(String name) {
        return name2OID.get(name);
    }

    /**
     * Return the java class object associated with the user friendly name.
     *
     * @param name the user friendly name.
     * @exception CertificateException if class cannot be instantiated.
     */
    public static Class<?> getClass(String name) throws CertificateException {
        String className = name2Class.get(name);
        if (className == null)
            return null;
        try {
            Class<?> extClass = Class.forName(className);
            return (extClass);
        } catch (Exception e) {
            throw new CertificateException("Error instantiating class for "
                                + name + " " + e.toString());
        }
    }

    /**
     * Return the java class object associated with the object identifier..
     *
     * @param oid the name of the object identifier to be returned.
     * @exception CertificateException if class cannot be instatiated.
     */
    public static Class<?> getClass(ObjectIdentifier oid)
            throws CertificateException {
        String name = getName(oid);
        if (name == null)
            return null;
        String className = name2Class.get(name);
        if (className == null)
            return null;
        try {
            Class<?> extClass = Class.forName(className);
            return (extClass);
        } catch (Exception e) {
            throw new CertificateException("Error instantiating class for "
                                   + name + " " + e.toString());
        }
    }
}
