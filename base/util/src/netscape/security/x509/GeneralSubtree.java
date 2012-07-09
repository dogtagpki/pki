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

import netscape.security.util.BigInt;
import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;
import netscape.security.util.PrettyPrintFormat;

/**
 * Represent the GeneralSubtree ASN.1 object, whose syntax is:
 *
 * <pre>
 * GeneralSubtree ::= SEQUENCE {
 *    base             GeneralName,
 *    minimum  [0]     BaseDistance DEFAULT 0,
 *    maximum  [1]     BaseDistance OPTIONAL
 * }
 * BaseDistance ::= INTEGER (0..MAX)
 * </pre>
 *
 * @version 1.5
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 */
public class GeneralSubtree implements Serializable {

    private static final long serialVersionUID = -2835481424013062770L;
    private static final byte TAG_MIN = 0;
    private static final byte TAG_MAX = 1;
    private static final int MIN_DEFAULT = 0;

    private GeneralName name;
    private int minimum = MIN_DEFAULT;
    private int maximum = -1;

    private transient PrettyPrintFormat pp = new PrettyPrintFormat(":");

    /**
     * The default constructor for the class.
     *
     * @param name the GeneralName
     * @param min the minimum BaseDistance
     * @param max the maximum BaseDistance
     */
    public GeneralSubtree(GeneralName name, int min, int max) {
        this.name = name;
        this.minimum = min;
        this.maximum = max;
    }

    /**
     * Create the object from its DER encoded form.
     *
     * @param val the DER encoded from of the same.
     */
    public GeneralSubtree(DerValue val) throws IOException {
        if (val.tag != DerValue.tag_Sequence) {
            throw new IOException("Invalid encoding for GeneralSubtree.");
        }
        name = new GeneralName(val.data.getDerValue());

        // NB. this is always encoded with the IMPLICIT tag
        // The checks only make sense if we assume implicit tagging,
        // with explicit tagging the form is always constructed.
        while (val.data.available() != 0) {
            DerValue opt = val.data.getDerValue();

            if (opt.isContextSpecific(TAG_MIN) && !opt.isConstructed()) {
                opt.resetTag(DerValue.tag_Integer);
                minimum = (opt.getInteger()).toInt();

            } else if (opt.isContextSpecific(TAG_MAX) && !opt.isConstructed()) {
                opt.resetTag(DerValue.tag_Integer);
                maximum = (opt.getInteger()).toInt();
            } else
                throw new IOException("Invalid encoding of GeneralSubtree.");
        }
    }

    /**
     * Return a printable string of the GeneralSubtree.
     */
    public String toString() {
        String s = "\n   GeneralSubtree: [\n" +
                "    GeneralName: " + ((name == null) ? "" : name.toString()) +
                "\n    Minimum: " + minimum;
        if (maximum == -1) {
            s += "\t    Maximum: undefined";
        } else
            s += "\t    Maximum: " + maximum;
        s += "    ]\n";
        return (s);
    }

    public String toPrint(int indent) {
        String s = "\n" + pp.indent(indent) + "GeneralSubtree: [\n" + pp.indent(indent + 2) +
                "GeneralName: " + ((name == null) ? "" : name.toString()) +
                "\n" + pp.indent(indent + 2) + "Minimum: " + minimum;
        if (maximum == -1) {
            s += "\n" + pp.indent(indent + 2) + "Maximum: undefined";
        } else
            s += "\n" + pp.indent(indent + 2) + "Maximum: " + maximum;
        s += "]\n";
        return (s);
    }

    /**
     * Encode the GeneralSubtree.
     *
     * @param out the DerOutputStream to encode this object to.
     */
    public void encode(DerOutputStream out) throws IOException {
        DerOutputStream seq = new DerOutputStream();

        name.encode(seq);

        if (minimum != MIN_DEFAULT) {
            DerOutputStream tmp = new DerOutputStream();
            tmp.putInteger(new BigInt(minimum));
            seq.writeImplicit(DerValue.createTag(DerValue.TAG_CONTEXT,
                              false, TAG_MIN), tmp);
        }
        if (maximum != -1) {
            DerOutputStream tmp = new DerOutputStream();
            tmp.putInteger(new BigInt(maximum));
            seq.writeImplicit(DerValue.createTag(DerValue.TAG_CONTEXT,
                              false, TAG_MAX), tmp);
        }
        out.write(DerValue.tag_Sequence, seq);
    }

    public GeneralName getGeneralName() {
        return name;
    }

    public int getMaxValue() {
        return maximum;
    }

    public int getMinValue() {
        return minimum;
    }
}
