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
package com.netscape.cms.authentication;

public class Crypt {
    // Static data:
    static byte[]
            IP = // Initial permutation
            {
                    58, 50, 42, 34, 26, 18, 10, 2,
                    60, 52, 44, 36, 28, 20, 12, 4,
                    62, 54, 46, 38, 30, 22, 14, 6,
                    64, 56, 48, 40, 32, 24, 16, 8,
                    57, 49, 41, 33, 25, 17, 9, 1,
                    59, 51, 43, 35, 27, 19, 11, 3,
                    61, 53, 45, 37, 29, 21, 13, 5,
                    63, 55, 47, 39, 31, 23, 15, 7
        },
            FP = // Final permutation, FP = IP^(-1)
            {
                    40, 8, 48, 16, 56, 24, 64, 32,
                    39, 7, 47, 15, 55, 23, 63, 31,
                    38, 6, 46, 14, 54, 22, 62, 30,
                    37, 5, 45, 13, 53, 21, 61, 29,
                    36, 4, 44, 12, 52, 20, 60, 28,
                    35, 3, 43, 11, 51, 19, 59, 27,
                    34, 2, 42, 10, 50, 18, 58, 26,
                    33, 1, 41, 9, 49, 17, 57, 25
        },
            // Permuted-choice 1 from the key bits to yield C and D.
            // Note that bits 8,16... are left out:
            // They are intended for a parity check.
            PC1_C =
        {
                57, 49, 41, 33, 25, 17, 9,
                1, 58, 50, 42, 34, 26, 18,
                10, 2, 59, 51, 43, 35, 27,
                19, 11, 3, 60, 52, 44, 36
        },
            PC1_D =
        {
                63, 55, 47, 39, 31, 23, 15,
                7, 62, 54, 46, 38, 30, 22,
                14, 6, 61, 53, 45, 37, 29,
                21, 13, 5, 28, 20, 12, 4
        },
            shifts = // Sequence of shifts used for the key schedule.
            {
                    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
        },
            // Permuted-choice 2, to pick out the bits from
            // the CD array that generate the key schedule.
            PC2_C =
        {
                14, 17, 11, 24, 1, 5,
                3, 28, 15, 6, 21, 10,
                23, 19, 12, 4, 26, 8,
                16, 7, 27, 20, 13, 2
        },
            PC2_D =
        {
                41, 52, 31, 37, 47, 55,
                30, 40, 51, 45, 33, 48,
                44, 49, 39, 56, 34, 53,
                46, 42, 50, 36, 29, 32
        },
            e2 = // The E-bit selection table. (see E below)
            {
                    32, 1, 2, 3, 4, 5,
                    4, 5, 6, 7, 8, 9,
                    8, 9, 10, 11, 12, 13,
                    12, 13, 14, 15, 16, 17,
                    16, 17, 18, 19, 20, 21,
                    20, 21, 22, 23, 24, 25,
                    24, 25, 26, 27, 28, 29,
                    28, 29, 30, 31, 32, 1
        },
            // P is a permutation on the selected combination of
            // the current L and key.
            P =
        {
                16, 7, 20, 21,
                29, 12, 28, 17,
                1, 15, 23, 26,
                5, 18, 31, 10,
                2, 8, 24, 14,
                32, 27, 3, 9,
                19, 13, 30, 6,
                22, 11, 4, 25
        };
    // The 8 selection functions.  For some reason, they gave a 0-origin
    // index, unlike everything else.
    static byte[][] S =
        {
                {
                        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
                        0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
                        4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
                        15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
                }, {
                        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
                        3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
                        0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
                        13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
                }, {
                        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
                        13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
                        13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
                        1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12
                }, {
                        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
                        13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
                        10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
                        3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
                }, {
                        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
                        14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
                        4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
                        11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3
                }, {
                        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
                        10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
                        9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
                        4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13
                }, {
                        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
                        13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
                        1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
                        6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12
                }, {
                        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
                        1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
                        7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
                        2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
                }
        };

    // Dynamic data:
    byte[] C = new byte[28], // The C and D arrays used to
            D = new byte[28], // calculate the key schedule.
            E = new byte[48], // The E bit-selection table.
            L = new byte[32], // The current block,
            R = new byte[32], //  divided into two halves.
            tempL = new byte[32],
            f = new byte[32],
            preS = new byte[48]; // The combination of the key and
    // the input, before selection.
    // The key schedule.  Generated from the key.
    byte[][] KS = new byte[16][48];

    // Object fields:
    String Passwd, Salt, Encrypt;

    // Public methods:
    /**
     * Create Crypt object with no passwd or salt set. Must use setPasswd()
     * and setSalt() before getEncryptedPasswd().
     */
    public Crypt() {
        Passwd = Salt = Encrypt = "";
    }

    /**
     * Create a Crypt object with specified salt. Use setPasswd() before
     * getEncryptedPasswd().
     *
     * @param salt the salt string for encryption
     */
    public Crypt(String salt) {
        Passwd = "";
        Salt = salt;
        Encrypt = crypt();
    }

    /**
     * Create a Crypt object with specified passwd and salt (often the
     * already encypted passwd). Get the encrypted result with
     * getEncryptedPasswd().
     *
     * @param passwd the passwd to encrypt
     * @param salt the salt string for encryption
     */
    public Crypt(String passwd, String salt) {
        Passwd = passwd;
        Salt = salt;
        Encrypt = crypt();
    }

    /**
     * Retrieve the passwd string currently being encrypted.
     *
     * @return the current passwd string
     */
    public String getPasswd() {
        return Passwd;
    }

    /**
     * Retrieve the salt string currently being used for encryption.
     *
     * @return the current salt string
     */
    public String getSalt() {
        return Salt;
    }

    /**
     * Retrieve the resulting encrypted string from the current passwd and
     * salt settings.
     *
     * @return the encrypted passwd
     */
    public String getEncryptedPasswd() {
        return Encrypt;
    }

    /**
     * Set a new passwd string for encryption. Use getEncryptedPasswd() to
     * retrieve the new result.
     *
     * @param passwd the new passwd string
     */
    public void setPasswd(String passwd) {
        Passwd = passwd;
        Encrypt = crypt();
    }

    /**
     * Set a new salt string for encryption. Use getEncryptedPasswd() to
     * retrieve the new result.
     *
     * @param salt the new salt string
     */
    public void setSalt(String salt) {
        Salt = salt;
        Encrypt = crypt();
    }

    // Internal crypt methods:
    String crypt() {
        if (Salt.length() == 0)
            return "";
        int i, j, pwi;
        byte c, temp;
        byte[] block = new byte[66], iobuf = new byte[16], salt = new byte[2], pw = Passwd.getBytes(), //jdk1.1
        saltbytes = Salt.getBytes(); //jdk1.1

        //	  pw = new byte[Passwd.length()],	//jdk1.0.2
        // saltbytes = new byte[Salt.length()];		//jdk1.0.2
        //Passwd.getBytes(0,Passwd.length(),pw,0);	//jdk1.0.2
        //Salt.getBytes(0,Salt.length(),saltbytes,0);	//jdk1.0.2

        salt[0] = saltbytes[0];
        salt[1] = (saltbytes.length > 1) ? saltbytes[1] : 0;

        for (i = 0; i < 66; i++)
            block[i] = 0;

        for (i = 0, pwi = 0; (pwi < pw.length) && (i < 64); pwi++, i++) {
            for (j = 0; j < 7; j++, i++) {
                block[i] = (byte) ((pw[pwi] >> (6 - j)) & 1);
            }
        }

        setkey(block);

        for (i = 0; i < 66; i++)
            block[i] = 0;

        for (i = 0; i < 2; i++) {
            c = salt[i];
            iobuf[i] = c;
            if (c > 'Z')
                c -= 6;
            if (c > '9')
                c -= 7;
            c -= '.';
            for (j = 0; j < 6; j++) {
                if (((c >> j) & 1) != 0) {
                    temp = E[6 * i + j];
                    E[6 * i + j] = E[6 * i + j + 24];
                    E[6 * i + j + 24] = temp;
                }
            }
        }

        for (i = 0; i < 25; i++) {
            encrypt(block, 0);
        }

        for (i = 0; i < 11; i++) {
            c = 0;
            for (j = 0; j < 6; j++) {
                c <<= 1;
                c |= block[6 * i + j];
            }
            c += '.';
            if (c > '9')
                c += 7;
            if (c > 'Z')
                c += 6;
            iobuf[i + 2] = c;
        }

        iobuf[i + 2] = 0;
        if (iobuf[1] == 0)
            iobuf[1] = iobuf[0];

        return new String(iobuf); //jdk1.1
        //return new String(iobuf,0);		//jdk1.0.2
    }

    void setkey(byte[] key) // Set up the key schedule from the key.
    {
        int i, j, k;
        byte t;

        // First, generate C and D by permuting the key.  The low order bit
        // of each 8-bit char is not used, so C and D are only 28 bits apiece.
        for (i = 0; i < 28; i++) {
            C[i] = key[PC1_C[i] - 1];
            D[i] = key[PC1_D[i] - 1];
        }

        // To generate Ki, rotate C and D according to schedule
        // and pick up a permutation using PC2.
        for (i = 0; i < 16; i++) {
            // rotate.
            for (k = 0; k < shifts[i]; k++) {
                t = C[0];
                for (j = 0; j < 27; j++)
                    C[j] = C[j + 1];
                C[27] = t;
                t = D[0];
                for (j = 0; j < 27; j++)
                    D[j] = D[j + 1];
                D[27] = t;
            }

            // get Ki. Note C and D are concatenated.
            for (j = 0; j < 24; j++) {
                KS[i][j] = C[PC2_C[j] - 1];
                KS[i][j + 24] = D[PC2_D[j] - 29];
            }
        }

        for (i = 0; i < 48; i++) {
            E[i] = e2[i];
        }
    }

    // The payoff: encrypt a block.
    void encrypt(byte[] block, int edflag) {
        int i, j, ii, t;
        byte k;

        // First, permute the bits in the input
        //for (j = 0; j < 64; j++)
        //{
        //    L[j] = block[IP[j]-1];
        //}
        for (j = 0; j < 32; j++)
            L[j] = block[IP[j] - 1];
        for (j = 32; j < 64; j++)
            R[j - 32] = block[IP[j] - 1];

        // Perform an encryption operation 16 times.
        for (ii = 0; ii < 16; ii++) {
            i = ii;
            // Save the R array, which will be the new L.
            for (j = 0; j < 32; j++)
                tempL[j] = R[j];
            // Expand R to 48 bits using the E selector;
            //  exclusive-or with the current key bits.
            for (j = 0; j < 48; j++)
                preS[j] = (byte) (R[E[j] - 1] ^ KS[i][j]);

            // The pre-select bits are now considered in 8 groups of
            // 6 bits each.  The 8 selection functions map these 6-bit
            // quantities into 4-bit quantities and the results permuted
            // to make an f(R, K).  The indexing into the selection functions
            // is peculiar; it could be simplified by rewriting the tables.
            for (j = 0; j < 8; j++) {
                t = 6 * j;
                k = S[j][(preS[t] << 5) +
                        (preS[t + 1] << 3) +
                        (preS[t + 2] << 2) +
                        (preS[t + 3] << 1) +
                        (preS[t + 4]) +
                        (preS[t + 5] << 4)];
                t = 4 * j;
                f[t] = (byte) ((k >> 3) & 1);
                f[t + 1] = (byte) ((k >> 2) & 1);
                f[t + 2] = (byte) ((k >> 1) & 1);
                f[t + 3] = (byte) ((k) & 1);
            }

            // The new R is L ^ f(R, K).
            // The f here has to be permuted first, though.
            for (j = 0; j < 32; j++) {
                R[j] = (byte) (L[j] ^ f[P[j] - 1]);
            }

            // Finally, the new L (the original R) is copied back.
            for (j = 0; j < 32; j++) {
                L[j] = tempL[j];
            }
        }

        // The output L and R are reversed.
        for (j = 0; j < 32; j++) {
            k = L[j];
            L[j] = R[j];
            R[j] = k;
        }

        // The final output gets the inverse permutation of the very original.
        for (j = 0; j < 64; j++) {
            //block[j] = L[FP[j]-1];
            block[j] = (FP[j] > 32) ? R[FP[j] - 33] : L[FP[j] - 1];
        }
    }
}
