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
package netscape.security.provider;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;
import java.security.spec.InvalidParameterSpecException;

import netscape.security.util.BigInt;
import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;

/**
 * This class implements the parameter set used by the
 * Digital Signature Algorithm as specified in the FIPS 186
 * standard.
 *
 * @author Jan Luehe
 *
 * @version 1.8, 97/12/10
 *
 * @since JDK1.2
 */

public class DSAParameters extends AlgorithmParametersSpi {

    // the prime (p)
    protected BigInteger p;

    // the sub-prime (q)
    protected BigInteger q;

    // the base (g)
    protected BigInteger g;

    protected void engineInit(AlgorithmParameterSpec paramSpec)
            throws InvalidParameterSpecException {
        if (!(paramSpec instanceof DSAParameterSpec)) {
            throw new InvalidParameterSpecException("Inappropriate parameter specification");
        }
        this.p = ((DSAParameterSpec) paramSpec).getP();
        this.q = ((DSAParameterSpec) paramSpec).getQ();
        this.g = ((DSAParameterSpec) paramSpec).getG();
    }

    protected void engineInit(byte[] params) throws IOException {
        DerValue encodedParams = new DerValue(params);

        if (encodedParams.tag != DerValue.tag_Sequence) {
            throw new IOException("DSA params parsing error");
        }

        encodedParams.data.reset();

        this.p = encodedParams.data.getInteger().toBigInteger();
        this.q = encodedParams.data.getInteger().toBigInteger();
        this.g = encodedParams.data.getInteger().toBigInteger();

        if (encodedParams.data.available() != 0) {
            throw new IOException("encoded params have " +
                    encodedParams.data.available() +
                    " extra bytes");
        }
    }

    protected void engineInit(byte[] params, String decodingMethod)
            throws IOException {
        engineInit(params);
    }

    @SuppressWarnings("unchecked")
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> paramSpec)
            throws InvalidParameterSpecException {
        try {
            Class<?> dsaParamSpec = Class.forName
                    ("java.security.spec.DSAParameterSpec");
            if (dsaParamSpec.isAssignableFrom(paramSpec)) {
                return (T) new DSAParameterSpec(this.p, this.q, this.g);
            } else {
                throw new InvalidParameterSpecException("Inappropriate parameter Specification");
            }
        } catch (ClassNotFoundException e) {
            throw new InvalidParameterSpecException("Unsupported parameter specification: " + e.getMessage());
        }
    }

    protected byte[] engineGetEncoded() throws IOException {
        try (DerOutputStream out = new DerOutputStream()) {
            DerOutputStream bytes = new DerOutputStream();

            bytes.putInteger(new BigInt(p.toByteArray()));
            bytes.putInteger(new BigInt(q.toByteArray()));
            bytes.putInteger(new BigInt(g.toByteArray()));
            out.write(DerValue.tag_Sequence, bytes);
            return out.toByteArray();
        }
    }

    protected byte[] engineGetEncoded(String encodingMethod)
            throws IOException {
        return engineGetEncoded();
    }

    /*
     * Returns a formatted string describing the parameters.
     */
    protected String engineToString() {
        return "\n\tp: " + new BigInt(p).toString()
                + "\n\tq: " + new BigInt(q).toString()
                + "\n\tg: " + new BigInt(g).toString()
                + "\n";
    }
}
