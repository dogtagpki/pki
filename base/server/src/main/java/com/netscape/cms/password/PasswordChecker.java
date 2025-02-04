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
package com.netscape.cms.password;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.netscape.certsrv.password.EPasswordCheckException;
import com.netscape.cmscore.apps.CMS;

/**
 * This class checks the given password if it meets the specific requirements.
 * For example, it can also specify the format of the password which has to
 * be 8 characters long and must be in alphanumeric.
 */
public class PasswordChecker {

    public enum PasswordQuality {
        CMS_PASSWORD_GOOD,
        CMS_PASSWORD_EMPTY_PASSWORD,
        CMS_PASSWORD_INVALID_LEN,
        CMS_PASSWORD_MISSING_UPPER_CASE,
        CMS_PASSWORD_MISSING_LOWER_CASE,
        CMS_PASSWORD_MISSING_NUMERIC,
        CMS_PASSWORD_MISSING_PUNCTUATION,
        CMS_PASSWORD_SEQUENCE,
        CMS_PASSWORD_REPEATED_CHAR,
        CMS_PASSWORD_CRACKLIB_FAILS
    }
    private int minSize = 8;
    private int minUpperLetter = 0;
    private int minLowerLetter = 0;
    private int minNumber = 0;
    private int minSpecialChar = 0;
    private int seqLength = 0;
    private int maxRepeatedChar = 0;
    private boolean cracklibCheck = false;

    private PasswordQuality quality;
    /**
     * Default constructor.
     */
    public PasswordChecker() {
    }

    public PasswordChecker(int minSize, int minUpperLetter, int minLowerLetter, int minNumber, int minSpecialChar,
            int seqLength, int maxRepeatedChar, boolean cracklibCheck) {
        this.minSize = minSize;
        this.minUpperLetter = minUpperLetter;
        this.minLowerLetter = minLowerLetter;
        this.minNumber = minNumber;
        this.minSpecialChar = minSpecialChar;
        this.seqLength = seqLength;
        this.maxRepeatedChar = maxRepeatedChar;
        this.cracklibCheck = cracklibCheck;
    }

    private PasswordQuality checkPassword(String password) throws EPasswordCheckException {
        if (password == null || password.length() == 0) {
            return PasswordQuality.CMS_PASSWORD_EMPTY_PASSWORD;
        }

        if (password.length() < minSize) {
            return PasswordQuality.CMS_PASSWORD_INVALID_LEN;
        }

        if (minUpperLetter > 0 && countLetters(password, "\\p{Upper}") < minUpperLetter) {
            return PasswordQuality.CMS_PASSWORD_MISSING_UPPER_CASE;
        }
        if (minLowerLetter > 0 && countLetters(password, "\\p{Lower}") < minLowerLetter) {
            return PasswordQuality.CMS_PASSWORD_MISSING_LOWER_CASE;
        }
        if (minNumber > 0 && countLetters(password, "\\d") < minNumber) {
            return PasswordQuality.CMS_PASSWORD_MISSING_NUMERIC;
        }
        if (minSpecialChar > 0 && countLetters(password, "\\p{Punct}") < minSpecialChar) {
            return PasswordQuality.CMS_PASSWORD_MISSING_PUNCTUATION;
        }


        if (seqLength > 0) {
            for (int i = 0; i< password.length() - (seqLength * 2); i++) {
                String seq = password.substring(i, i + seqLength);
                String invSeq = new StringBuilder(seq).reverse().toString();
                if(password.indexOf(seq, i + seqLength) > 0 || password.indexOf(invSeq, i + seqLength) > 0){
                    return PasswordQuality.CMS_PASSWORD_SEQUENCE;
                }
            }
        }

        if (maxRepeatedChar > 0) {
            int mostRepeatedChar = 0;
            char last = 0;
            for (char c: password.toCharArray()) {
                if (c == last) {
                    mostRepeatedChar ++;
                    if (maxRepeatedChar < mostRepeatedChar) {
                        return PasswordQuality.CMS_PASSWORD_REPEATED_CHAR;
                    }
                } else {
                    mostRepeatedChar = 1;
                    last = c;
                }
            }
        }

        if (cracklibCheck) {
            try {
                Process crack = new ProcessBuilder("/usr/sbin/cracklib-check").start();
                BufferedWriter crackIn = crack.outputWriter();
                BufferedReader crackOut = crack.inputReader();
                crackIn.write(password);
                crackIn.close();

                String crackResult = crackOut.readLine().substring(password.length() + 2);
                if (!crackResult.equals("OK")) {
                    return PasswordQuality.CMS_PASSWORD_CRACKLIB_FAILS;
                }

            } catch (IOException e) {
                throw new EPasswordCheckException("Impossible check password with cracklib.", e);
            }

        }
        return PasswordQuality.CMS_PASSWORD_GOOD;
   }

    private int countLetters(String password, String pattern) {
        int count = 0;
        Pattern patt = Pattern.compile(pattern);
        Matcher matcher = patt.matcher(password);
        while (matcher.find()) {
            count++;
        }
        return count;
    }

    /**
     * Returns true if the given password meets the quality requirement;
     * otherwise returns false.
     *
     * @param pwd The given password being checked.
     * @return true if the password meets the quality requirement; otherwise
     *         returns false.
     * @throws EPasswordCheckException If there is a configuration problem with the password checker
     */
    public boolean isGoodPassword(String pwd) throws EPasswordCheckException {
        quality = checkPassword(pwd);
        return quality == PasswordQuality.CMS_PASSWORD_GOOD;
    }

    /**
     * Returns a reason if the password doesn't meet the quality requirement.
     *
     * @return string as a reason if the password quality requirement is not met.
     */
    public String getReason() {
        return getReason(null);
    }

    /**
     * Returns a reason if the password doesn't meet the quality requirement.
     *
     * @param loc
     * @return string as a reason if the password quality requirement is not met.
     */
    public String getReason(Locale loc) {
        return switch (quality) {
        case CMS_PASSWORD_INVALID_LEN -> new EPasswordCheckException(
                CMS.getUserMessage(loc,"CMS_PASSWORD_INVALID_LEN", "" + minSize)).toString();
        case CMS_PASSWORD_MISSING_UPPER_CASE -> new EPasswordCheckException(
                CMS.getUserMessage(loc,"CMS_PASSWORD_MISSING_UPPER_CASE", "" + minUpperLetter)).toString();
        case CMS_PASSWORD_MISSING_LOWER_CASE -> new EPasswordCheckException(
                CMS.getUserMessage(loc,"CMS_PASSWORD_MISSING_LOWER_CASE", "" + minLowerLetter)).toString();
        case CMS_PASSWORD_MISSING_NUMERIC -> new EPasswordCheckException(
                CMS.getUserMessage(loc,"CMS_PASSWORD_MISSING_NUMERIC", "" + minNumber)).toString();
        case CMS_PASSWORD_MISSING_PUNCTUATION -> new EPasswordCheckException(
                CMS.getUserMessage(loc,"CMS_PASSWORD_MISSING_PUNCTUATION", "" + minSpecialChar)).toString();
        case CMS_PASSWORD_REPEATED_CHAR -> new EPasswordCheckException(
                CMS.getUserMessage(loc,"CMS_PASSWORD_REPEATED_CHAR", "" + maxRepeatedChar)).toString();
        case CMS_PASSWORD_SEQUENCE, CMS_PASSWORD_CRACKLIB_FAILS -> new EPasswordCheckException(
                CMS.getUserMessage(loc, quality.name())).toString();
        default -> null;
        };
    }

    public int getMinSize() {
        return minSize;
    }

    public void setMinSize(int minSize) {
        this.minSize = minSize;
    }

    public int getMinUpperLetter() {
        return minUpperLetter;
    }

    public void setMinUpperLetter(int minUpperLetter) {
        this.minUpperLetter = minUpperLetter;
    }

    public int getMinLowerLetter() {
        return minLowerLetter;
    }

    public void setMinLowerLetter(int minLowerLetter) {
        this.minLowerLetter = minLowerLetter;
    }

    public int getMinNumber() {
        return minNumber;
    }

    public void setMinNumber(int minNumber) {
        this.minNumber = minNumber;
    }

    public int getMinSpecialChar() {
        return minSpecialChar;
    }

    public void setMinSpecialChar(int minSpecialChar) {
        this.minSpecialChar = minSpecialChar;
    }

    public int getSeqLength() {
        return seqLength;
    }

    public void setSeqLength(int seqLength) {
        this.seqLength = seqLength;
    }

    public int getMaxRepeatedChar() {
        return maxRepeatedChar;
    }

    public void setMaxRepeatedChar(int maxRepeatedChar) {
        this.maxRepeatedChar = maxRepeatedChar;
    }

    public boolean isCracklibCheck() {
        return cracklibCheck;
    }

    public void setCracklibCheck(boolean cracklibCheck) {
        this.cracklibCheck = cracklibCheck;
    }


}
