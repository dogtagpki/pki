package com.netscape.cmstools.cert;

import java.util.Arrays;
import java.util.Collection;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.ParseException;

import com.netscape.certsrv.profile.ProfileDataInfo;
import com.netscape.certsrv.profile.ProfileDataInfos;
import com.netscape.cmstools.cli.CLI;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.profile.ProfileCLI;

public class CertRequestProfileFindCLI extends CLI {

    public CertCLI certCLI;

    public CertRequestProfileFindCLI(CertCLI certCLI) {
        super("request-profile-find", "List Enrollment templates", certCLI);
        this.certCLI = certCLI;

        createOptions();
    }

    public void printHelp() {
        formatter.printHelp(getFullName() + " <Profile ID> [OPTIONS...]", options);
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
            // Display usage
            printHelp();
            System.exit(0);
        }

        CommandLine cmd = null;

        try {
            cmd = parser.parse(options, args);

        } catch (ParseException e) {
            System.err.println("Error: " + e.getMessage());
            printHelp();
            System.exit(-1);
        }

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 1) {
            System.err.println("Error: Missing Profile ID.");
            printHelp();
            System.exit(-1);
        }

        String s = cmd.getOptionValue("start");
        Integer start = s == null ? null : Integer.valueOf(s);

        s = cmd.getOptionValue("size");
        Integer size = s == null ? null : Integer.valueOf(s);

        ProfileDataInfos response = certCLI.certClient.listEnrollmentTemplates(start, size);

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

