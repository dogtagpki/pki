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
import java.util.Enumeration;
import java.util.Vector;

import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;

/**
 * This object class represents the GeneralNames type required in
 * X509 certificates.  
 * <p>The ASN.1 syntax for this is:
 * <pre>
 * GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
 * </pre>
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 * @version 1.7
 */
public class GeneralNames extends Vector {
    /**
     * Create the GeneralNames, decoding from the passed DerValue.
	 *
	 * <b>Caution when using this constructor. It may be broken!
	 * Better to call addElement(gni) directly where gni is
	 * a GeneralNameInterface object </b>
     *
     * @param derVal the DerValue to construct the GeneralNames from.
     * @exception GeneralNamesException on decoding error.
     * @exception IOException on error.
     */
    public GeneralNames(DerValue derVal)
    throws IOException, GeneralNamesException {
        if (derVal.tag != DerValue.tag_Sequence) {
            throw new IOException("Invalid encoding for GeneralNames.");
        }
        if (derVal.data.available() == 0) {
            throw new GeneralNamesException("No data available in "
                                      + "passed DER encoded value.");
        }
        // Decode all the GeneralName's
        while (derVal.data.available() != 0) {
            DerValue encName = derVal.data.getDerValue();

            GeneralName name = new GeneralName(encName);
            addElement(name);
        }
    }

	/**
	 * Create the GeneralNames
	 *
	 * @param names a non-empty array of names to put into the
	 *   generalNames
	 */

	public GeneralNames(GeneralNameInterface[] names) 
	throws  GeneralNamesException {
		if (names == null || names.length==0)
			throw new GeneralNamesException("Cannot create empty GeneralNames");

		for (int i=0;i<names.length;i++) {
			addElement(names[i]);
		}
	}



    /**
     * The default constructor for this class.
     */
    public GeneralNames() {
        super(1,1);
    }

    /**
     * Write the extension to the DerOutputStream.
     *
     * @param out the DerOutputStream to write the extension to.
     * @exception GeneralNamesException on encoding error.
     * @exception IOException on error.
     */
    public void encode(DerOutputStream out)
    throws IOException, GeneralNamesException {
        if (size() == 0) { return; }

        Enumeration names = elements();
        DerOutputStream temp = new DerOutputStream();

        while (names.hasMoreElements()) {
            Object obj = names.nextElement();
            if (!(obj instanceof GeneralNameInterface)) {
	        throw new GeneralNamesException("Element in GeneralNames "
                                         + "not of type GeneralName.");
            }
			GeneralNameInterface intf = (GeneralNameInterface)obj;
			if (obj instanceof GeneralName) {
				intf.encode(temp);
			} else {
				DerOutputStream gname = new DerOutputStream();
				intf.encode(gname);
				int nameType = intf.getType();
				// constructed form
				if (nameType == GeneralNameInterface.NAME_ANY ||
					nameType == GeneralNameInterface.NAME_X400 ||
					nameType == GeneralNameInterface.NAME_EDI) {

					temp.writeImplicit(DerValue.createTag(DerValue.TAG_CONTEXT,
                             true, (byte)nameType), gname);
				} else if ( nameType == GeneralNameInterface.NAME_DIRECTORY ) {
					// EXPLICIT tag because directoryName is a CHOICE
					temp.write(DerValue.createTag(DerValue.TAG_CONTEXT,
                             true, (byte)nameType), gname);
				} else // primitive form
					temp.writeImplicit(DerValue.createTag(DerValue.TAG_CONTEXT,
                             false, (byte)nameType), gname);
			}

        }
		
        out.write(DerValue.tag_Sequence,temp);
    }
}
