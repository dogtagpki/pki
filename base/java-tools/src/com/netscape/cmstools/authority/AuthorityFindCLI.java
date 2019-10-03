package com.netscape.cmstools.authority;

import java.util.List;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CommandCLI;

import com.netscape.certsrv.authority.AuthorityClient;
import com.netscape.certsrv.authority.AuthorityData;
import com.netscape.cmstools.cli.MainCLI;

public class AuthorityFindCLI extends CommandCLI {

    public AuthorityCLI authorityCLI;

    public AuthorityFindCLI(AuthorityCLI authorityCLI) {
        super("find", "Find CAs", authorityCLI);
        this.authorityCLI = authorityCLI;
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

    public void execute(CommandLine cmd) throws Exception {

        String id = cmd.getOptionValue("id");
        String parentID = cmd.getOptionValue("parent-id");
        String dn = cmd.getOptionValue("dn");
        String issuerDN = cmd.getOptionValue("issuer-dn");

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        AuthorityClient authorityClient = authorityCLI.getAuthorityClient();
        List<AuthorityData> datas = authorityClient.findCAs(id, parentID, dn, issuerDN);

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
