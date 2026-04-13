package com.netscape.cmstools.authority;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.netscape.certsrv.authority.AuthorityClient;
import com.netscape.certsrv.authority.AuthorityData;
import com.netscape.certsrv.ca.AuthorityID;
import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.SubsystemClient;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;

public class AuthorityCreateCLI extends SubsystemCommandCLI {

    public AuthorityCLI authorityCLI;

    public AuthorityCreateCLI(AuthorityCLI authorityCLI) {
        super("create", "Create CAs", authorityCLI);
        this.authorityCLI = authorityCLI;
    }

    @Override
    public void createOptions() {

        super.createOptions();

        Option optParent = new Option(null, "parent", true, "ID of parent CA");
        optParent.setArgName("id");
        options.addOption(optParent);

        Option optDesc = new Option(null, "desc", true, "Optional description");
        optDesc.setArgName("string");
        options.addOption(optDesc);

        Option optCsrFile = new Option(null, "csr-file", true,
                "PEM file containing a CSR for an externally-held CA key. " +
                "When provided, Dogtag signs the CSR as a sub-CA certificate " +
                "without generating a local key pair.");
        optCsrFile.setArgName("path");
        options.addOption(optCsrFile);

        Option optProfile = new Option(null, "profile", true,
                "Signing profile for the sub-CA certificate " +
                "(default: caExternalKeyCACert with --csr-file, caCACert otherwise)");
        optProfile.setArgName("id");
        options.addOption(optProfile);
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " <dn>", options);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length < 1) {
            throw new Exception("No DN specified.");

        } else if (cmdArgs.length > 1) {
            throw new Exception("Too many arguments.");
        }

        String parentAIDString = null;
        if (cmd.hasOption("parent")) {
            parentAIDString = cmd.getOptionValue("parent");
            try {
                new AuthorityID(parentAIDString);
            } catch (IllegalArgumentException e) {
                throw new Exception("Bad CA ID: " + parentAIDString, e);
            }
        } else {
            throw new Exception("Must specify parent authority");
        }

        String desc = null;
        if (cmd.hasOption("desc"))
            desc = cmd.getOptionValue("desc");

        String csrData = null;
        if (cmd.hasOption("csr-file")) {
            String csrFile = cmd.getOptionValue("csr-file");
            csrData = new String(Files.readAllBytes(Paths.get(csrFile)), StandardCharsets.UTF_8);
        }

        String profileId = null;
        if (cmd.hasOption("profile"))
            profileId = cmd.getOptionValue("profile");

        String dn = cmdArgs[0];

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        AuthorityData data = new AuthorityData(
            null, dn, null, parentAIDString, null, null, true /* enabled */, desc, null);
        if (csrData != null)
            data.setCsrData(csrData);
        if (profileId != null)
            data.setProfileId(profileId);

        PKIClient client = getPKIClient();
        SubsystemClient subsystemClient = getSubsystemClient(client);
        AuthorityClient authorityClient = new AuthorityClient(subsystemClient);
        AuthorityData newData = authorityClient.createCA(data);
        AuthorityCLI.printAuthorityData(newData);
    }
}
