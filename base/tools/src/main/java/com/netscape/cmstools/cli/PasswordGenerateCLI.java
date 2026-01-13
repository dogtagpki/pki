//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.cli;

import java.io.FileOutputStream;
import java.io.PrintStream;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CommandCLI;

public class PasswordGenerateCLI extends CommandCLI {

    /**
     * The FIPS_MIN_PIN is defined in the following file:
     * https://dxr.mozilla.org/nss/source/nss/lib/softoken/pkcs11i.h
     */
    public static final int FIPS_MIN_PIN = 7;

    /**
     * Valid punctuation characters for random password.
     *
     * This is based on Python's string.punctuation except:
     * - equal sign since it's used as delimiter in password.conf
     * - backslash since it's causing SSL handshake failure
     * - it should be relatively safe in an XML attribute
     */
    public static final String PUNCTUATIONS = "!#*+,-./:;^_|~";

    public PasswordGenerateCLI(PasswordCLI passwordCLI) {
        super("generate", "Generate secure random password", passwordCLI);
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    @Override
    public void createOptions() {

        super.createOptions();

        Option option = new Option(null, "characters", true, "Valid password characters");
        option.setArgName("characters");
        options.addOption(option);

        option = new Option(null, "length", true, "Password length (default: 12)");
        option.setArgName("length");
        options.addOption(option);

        option = new Option(null, "output-file", true, "Output file");
        option.setArgName("file");
        options.addOption(option);
    }

    char getDigit(int index) {
        return (char) ('0' + index);
    }

    char getLowerCaseLetter(int index) {
        return (char) ('a' + index);
    }

    char getUpperCaseLetter(int index) {
        return (char) ('A' + index);
    }

    char getPunctuation(int index) {
        return PUNCTUATIONS.charAt(index);
    }

    /**
     * This function generates FIPS-compliant password.
     *
     * See sftk_newPinCheck() in the following file:
     * https://dxr.mozilla.org/nss/source/nss/lib/softoken/fipstokn.c
     *
     * The minimum password length is FIPS_MIN_PIN Unicode characters.
     *
     * The password must contain at least 3 character classes:
     * - digits (0-9)
     * - ASCII lowercase letters
     * - ASCII uppercase letters
     * - ASCII non-alphanumeric characters (such as space and punctuation marks)
     * - non-ASCII characters
     *
     * If an ASCII uppercase letter is the first character of the password,
     * the uppercase letter is not counted toward its character class.
     *
     * If a digit is the last character of the password, the digit is not
     * counted toward its character class.
     */
    char[] generatePassword(Random random, int length) {

        logger.info("Generating password with default characters");

        List<Character> chars = new ArrayList<>();

        // add 1 random char from each char class to meet
        // the minimum number of char class requirement
        int index = random.nextInt(10);
        char randomChar = getDigit(index);
        chars.add(randomChar);

        index = random.nextInt(26);
        randomChar = getLowerCaseLetter(index);
        chars.add(randomChar);

        index = random.nextInt(26);
        randomChar = getUpperCaseLetter(index);
        chars.add(randomChar);

        index = random.nextInt(PUNCTUATIONS.length());
        randomChar = getPunctuation(index);
        chars.add(randomChar);

        // extend chars to specified length via any valid character classes
        while (chars.size() < length) {

            // generate random index
            index = random.nextInt(10 + 26 + 26 + PUNCTUATIONS.length());

            // generate random char based on the index
            if (index < 10) {
                randomChar = getDigit(index);

            } else if (index < 10 + 26) {
                randomChar = getLowerCaseLetter(index - 10);

            } else if (index < 10 + 26 + 26) {
                randomChar = getUpperCaseLetter(index - 10 - 26);

            } else {
                randomChar = getPunctuation(index - 10 - 26 - 26);
            }

            chars.add(randomChar);
        }

        // randomize the char order
        Collections.shuffle(chars, random);

        char[] password = new char[chars.size()];
        for (int i = 0; i < chars.size(); i++) {
            password[i] = chars.get(i);
        }

        return password;
    }

    /**
     * This function generates password with the given characters.
     */
    char[] generatePassword(Random random, String characters, int length) {

        logger.info("Generating password with user-provided characters");

        List<Character> password = new ArrayList<>();

        // extend chars to specified length via any valid character classes
        while (password.size() < length) {

            // generate random index
            int index = random.nextInt(characters.length());

            // generate random char based on the index
            char randomChar = characters.charAt(index);

            password.add(randomChar);
        }

        char[] chars = new char[password.size()];
        for (int i = 0; i < password.size(); i++) {
            chars[i] = password.get(i);
        }

        return chars;
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String characters = cmd.getOptionValue("characters");

        String value = cmd.getOptionValue("length", "12");
        int length = Integer.parseInt(value);

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        SecureRandom random = SecureRandom.getInstance("pkcs11prng", "Mozilla-JSS");

        char[] chars;
        if (characters == null) {
            chars = generatePassword(random, length);
        } else {
            chars = generatePassword(random, characters, length);
        }

        String password = new String(chars);

        String outputFile = cmd.getOptionValue("output-file");
        if (outputFile != null) {
            try (PrintStream out = new PrintStream(new FileOutputStream(outputFile))) {
                out.println(password);
            }

        } else {
            System.out.println(password);
        }
    }
}
