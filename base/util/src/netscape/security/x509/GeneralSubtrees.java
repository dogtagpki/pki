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
import java.io.Serializable;
import java.util.Enumeration;
import java.util.Vector;

import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;
import netscape.security.util.PrettyPrintFormat;

/**
 * Represent the GeneralSubtrees ASN.1 object.
 *
 * @version 1.4
 *
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 */
public class GeneralSubtrees implements Serializable {

    private static final long serialVersionUID = 6308776640697100848L;
    private Vector<GeneralSubtree> trees;
    private transient PrettyPrintFormat pp = new PrettyPrintFormat(":");

    /**
     * The default constructor for the class.
     *
     * @param trees the sequence of GeneralSubtree.
     */
    public GeneralSubtrees(Vector<GeneralSubtree> trees) {
        this.trees = trees;
    }

    /**
     * Create the object from the passed DER encoded form.
     *
     * @param val the DER encoded form of the same.
     */
    public GeneralSubtrees(DerValue val) throws IOException {
        trees = new Vector<GeneralSubtree>(1, 1);
        if (val.tag != DerValue.tag_Sequence) {
            throw new IOException("Invalid encoding of GeneralSubtrees.");
        }
        while (val.data.available() != 0) {
            DerValue opt = val.data.getDerValue();
            GeneralSubtree tree = new GeneralSubtree(opt);
            trees.addElement(tree);
        }
    }

    /**
     * Return a printable string of the GeneralSubtree.
     */
    public String toString() {
        String s = "   GeneralSubtrees:\n" + trees.toString()
                   + "\n";

        return (s);
    }

    public String toPrint(int indent) {

        StringBuffer s = new StringBuffer();
        GeneralSubtree element;

        for (Enumeration<GeneralSubtree> e = trees.elements(); e.hasMoreElements();) {
            element = e.nextElement();
            s.append(pp.indent(indent + 4) + element.toPrint(indent) + "\n");
        }

        return (s.toString());
    }

    /**
     * Encode the GeneralSubtrees.
     *
     * @param out the DerOutputStrean to encode this object to.
     */
    public void encode(DerOutputStream out) throws IOException {
        DerOutputStream seq = new DerOutputStream();

        for (int i = 0; i < trees.size(); i++) {
            trees.elementAt(i).encode(seq);
        }
        out.write(DerValue.tag_Sequence, seq);
    }

    public Vector<GeneralSubtree> getSubtrees() {
        return trees;
    }
}
