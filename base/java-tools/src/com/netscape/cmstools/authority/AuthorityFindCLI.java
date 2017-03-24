package com.netscape.cmstools.authority;

import java.util.Arrays;
import java.util.List;

import org.apache.commons.cli.CommandLine;

import com.netscape.certsrv.authority.AuthorityClient;
import com.netscape.certsrv.authority.AuthorityData;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;

public class AuthorityFindCLI extends CLI {

    public AuthorityCLI authorityCLI;

    public AuthorityFindCLI(AuthorityCLI authorityCLI) {
        super("find", "Find CAs", authorityCLI);
        this.authorityCLI = authorityCLI;
    }

    public void printHelp() {
        formatter.printHelp(getFullName(), options);
    }

    public void execute(String[] args) throws Exception {
        // Always check for "--help" prior to parsing
        if (Arrays.asList(args).contains("--help")) {
            printHelp();
            return;
        }

        @SuppressWarnings("unused")
        CommandLine cmd = parser.parse(options, args);

        AuthorityClient authorityClient = authorityCLI.getAuthorityClient();
        List<AuthorityData> datas = authorityClient.listCAs();

        MainCLI.printMessage(datas.size() + " entries matched");
        if (datas.size() == 0) return;

        boolean first = true;
        for (AuthorityData data : datas) {
            if (first)
                first = false;
            else
                System.out.println();
            AuthorityCLI.printAuthorityData(data);
        }

        MainCLI.printMessage("Number of entries returned " + datas.size());
    }

}
