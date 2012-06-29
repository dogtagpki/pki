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
package netscape.security.util;

import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.util.Locale;
import java.util.ResourceBundle;

import netscape.security.provider.RSAPublicKey;
import netscape.security.x509.X509Key;

/**
 * This class will display the certificate content in predefined
 * format.
 *
 * @author Jack Pan-Chen
 * @author Andrew Wnuk
 * @version $Revision$, $Date$
 */
public class PubKeyPrettyPrint {

    /*==========================================================
     * variables
     *==========================================================*/
    private X509Key mX509Key = null;
    private PrettyPrintFormat pp = null;

    /*==========================================================
     * constructors
     *==========================================================*/

    public PubKeyPrettyPrint(PublicKey key) {
        if (key instanceof X509Key)
            mX509Key = (X509Key) key;

        pp = new PrettyPrintFormat(":");
    }

    /*==========================================================
     * public methods
     *==========================================================*/

    /**
     * This method return string representation of the certificate
     * in predefined format using specified client local. I18N Support.
     *
     * @param clientLocale Locale to be used for localization
     * @return string representation of the certificate
     */
    public String toString(Locale clientLocale, int indentSize, int lineLen) {

        if (mX509Key != null)
            return X509toString(clientLocale, indentSize, lineLen);
        else
            return null;
    }

    public String X509toString(Locale clientLocale, int indentSize, int lineLen) {

        //get I18N resources
        ResourceBundle resource = ResourceBundle.getBundle(
                PrettyPrintResources.class.getName());

        StringBuffer sb = new StringBuffer();

        try {
            String alg = mX509Key.getAlgorithm();

            //XXX I18N Algorithm Name ?
            sb.append(pp.indent(indentSize) + resource.getString(
                    PrettyPrintResources.TOKEN_ALGORITHM) +
                    alg + " - " +
                    mX509Key.getAlgorithmId().getOID().toString() + "\n");

            if (alg.equals("RSA")) {

                RSAPublicKey rsakey = new RSAPublicKey(mX509Key.getEncoded());

                sb.append(pp.indent(indentSize) + resource.getString(
                        PrettyPrintResources.TOKEN_PUBLIC_KEY) + "\n");
                sb.append(pp.indent(indentSize + 4) + resource.getString(
                        PrettyPrintResources.TOKEN_PUBLIC_KEY_EXPONENT) +
                        rsakey.getPublicExponent().toInt() + "\n");
                sb.append(pp.indent(indentSize + 4) + resource.getString(
                        PrettyPrintResources.TOKEN_PUBLIC_KEY_MODULUS) +
                        "(" + rsakey.getKeySize() + " bits) :\n");
                sb.append(pp.toHexString(
                        rsakey.getModulus().toByteArray(),
                        indentSize + 8, lineLen));
            } else {

                // DSAPublicKey is more complicated to decode, since
                // the DSAParams (PQG) is not fully decoded.
                // So, we just print the entire public key blob

                sb.append(pp.indent(indentSize) + resource.getString(
                        PrettyPrintResources.TOKEN_PUBLIC_KEY) + "\n");
                sb.append(pp.toHexString(mX509Key.getKey(), indentSize + 4, lineLen));
            }

        } catch(InvalidKeyException e){
            e.printStackTrace();
        }

        return sb.toString();
    }
}
