package com.netscape.cmstools.ca;

import java.util.Arrays;
import java.util.Collection;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.dogtagpki.cli.CLI;

import com.netscape.certsrv.ca.CACertClient;
import com.netscape.certsrv.profile.ProfileDataInfo;
import com.netscape.certsrv.profile.ProfileDataInfos;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.profile.ProfileCLI;

public class CACertRequestProfileFindCLI extends CLI {

    public CACertCLI certCLI;

    public CACertRequestProfileFindCLI(CACertCLI certCLI) {
        super("request-profile-find", "List Enrollment templates", certCLI);
        this.certCLI = certCLI;

        createOptions();
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    public void createOptions() {
        Option option = new Option(null, "start", true, "Page start");
        option.setArgName("start");
        options.addOption(option);

        option = new Option(null, "size", true, "Page size");
        option.setArgName("size");
        options.addOption(option);
    }

    public void execute(String[] args) throws Exception {
        // Always check for "--help" prior to parsing
        if (Arrays.asList(args).contains("--help")) {
            printHelp();
            return;
        }

        CommandLine cmd = parser.parse(options, args);

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 0) {
            throw new Exception("Too many arguments specified.");
        }

        String s = cmd.getOptionValue("start");
        Integer start = s == null ? null : Integer.valueOf(s);

        s = cmd.getOptionValue("size");
        Integer size = s == null ? null : Integer.valueOf(s);

        CACertClient certClient = certCLI.getCertClient();
        ProfileDataInfos response = certClient.listEnrollmentTemplates(start, size);

        MainCLI.printMessage(response.getTotal() + " entries matched");
        if (response.getTotal() == 0) return;

        Collection<ProfileDataInfo> infos = response.getEntries();
        boolean first = true;

        for (ProfileDataInfo info: infos) {
            if (first) {
                first = false;
            } else {
                System.out.println();
            }
            ProfileCLI.printProfileDataInfo(info);
        }

        MainCLI.printMessage("Number of entries returned " + infos.size());
    }
}

