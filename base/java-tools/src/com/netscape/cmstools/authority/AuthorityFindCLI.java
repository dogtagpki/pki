package com.netscape.cmstools.authority;

import java.util.Arrays;
import java.util.Collection;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.netscape.certsrv.authority.AuthorityClient;
import com.netscape.certsrv.authority.AuthorityData;
import com.netscape.certsrv.authority.AuthoritySearchRequest;
import com.netscape.certsrv.authority.AuthoritySearchResponse;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

public class AuthorityFindCLI extends CLI {

    public AuthorityCLI authorityCLI;

    public AuthorityFindCLI(AuthorityCLI authorityCLI) {
        super("find", "Find CAs", authorityCLI);
        this.authorityCLI = authorityCLI;

        createOptions();
    }

    public void printHelp() {
        formatter.printHelp(getFullName(), options);
    }

    public void createOptions() {
        Option option = new Option(null, "id", true, "Authority ID");
        option.setArgName("ID");
        options.addOption(option);

        option = new Option(null, "parent-id", true, "Authority parent ID");
        option.setArgName("ID");
        options.addOption(option);

        option = new Option(null, "dn", true, "Authority DN");
        option.setArgName("DN");
        options.addOption(option);

        option = new Option(null, "issuer-dn", true, "Authority issuer DN");
        option.setArgName("DN");
        options.addOption(option);
    }

    public void execute(String[] args) throws Exception {
        // Always check for "--help" prior to parsing
        if (Arrays.asList(args).contains("--help")) {
            printHelp();
            return;
        }

        CommandLine cmd = parser.parse(options, args);

        AuthoritySearchRequest request = new AuthoritySearchRequest();

        String id = cmd.getOptionValue("id");
        request.setID(id);

        String parentID = cmd.getOptionValue("parent-id");
        request.setParentID(parentID);

        String dn = cmd.getOptionValue("dn");
        request.setDN(dn);

        String issuerDN = cmd.getOptionValue("issuer-dn");
        request.setIssuerDN(issuerDN);

        AuthorityClient authorityClient = authorityCLI.getAuthorityClient();
        AuthoritySearchResponse response = authorityClient.findCAs(request);

        MainCLI.printMessage(response.getTotal() + " entries matched");
        if (response.getTotal() == 0) return;

        Collection<AuthorityData> entries = response.getEntries();
        boolean first = true;

        for (AuthorityData data : entries) {
            if (first)
                first = false;
            else
                System.out.println();
            AuthorityCLI.printAuthorityData(data);
        }

        MainCLI.printMessage("Number of entries returned " + entries.size());
    }

}
