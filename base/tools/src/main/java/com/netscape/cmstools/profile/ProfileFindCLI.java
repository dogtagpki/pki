package com.netscape.cmstools.profile;

import java.util.Collection;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;

import com.netscape.certsrv.client.PKIClient;
import com.netscape.certsrv.client.SubsystemClient;
import com.netscape.certsrv.profile.ProfileClient;
import com.netscape.certsrv.profile.ProfileDataInfo;
import com.netscape.certsrv.profile.ProfileDataInfos;
import com.netscape.cmstools.cli.MainCLI;
import com.netscape.cmstools.cli.SubsystemCommandCLI;

public class ProfileFindCLI extends SubsystemCommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ProfileFindCLI.class);

    public ProfileCLI profileCLI;

    public ProfileFindCLI(ProfileCLI profileCLI) {
        super("find", "Find profiles", profileCLI);
        this.profileCLI = profileCLI;

        createOptions();
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    @Override
    public void createOptions() {
        Option option = new Option(null, "start", true, "Page start");
        option.setArgName("start");
        options.addOption(option);

        option = new Option(null, "size", true, "Page size");
        option.setArgName("size");
        options.addOption(option);

        option = new Option(null, "visible", true, "Profile with visible value");
        option.setArgName("true/false");
        options.addOption(option);

        option = new Option(null, "enable", true, "Profile with enable value");
        option.setArgName("true/false");
        options.addOption(option);

        option = new Option(null, "enableBy", true, "Only enabled by the user");
        option.setArgName("user");
        options.addOption(option);
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        String[] cmdArgs = cmd.getArgs();

        if (cmdArgs.length != 0) {
            throw new Exception("Too many arguments specified.");
        }

        String s = cmd.getOptionValue("start");
        Integer start = s == null ? null : Integer.valueOf(s);

        s = cmd.getOptionValue("size");
        Integer size = s == null ? null : Integer.valueOf(s);

        Boolean visible = cmd.hasOption("visible") ? Boolean.valueOf(cmd.getOptionValue("visible")) : null;
        Boolean enable = cmd.hasOption("enable") ? Boolean.valueOf(cmd.getOptionValue("enable")) : null;
        String enableBy = cmd.getOptionValue("enableBy");

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        PKIClient client = mainCLI.getClient();
        SubsystemClient subsystemClient = profileCLI.caCLI.getSubsystemClient(client);
        ProfileClient profileClient = new ProfileClient(subsystemClient);
        ProfileDataInfos response = profileClient.listProfiles(start, size, visible, enable, enableBy);

        Integer total = response.getTotal();
        if (total != null) {
            MainCLI.printMessage(total + " entries matched");
            if (total == 0) return;
        }

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
