import org.junit.runner.RunWith;
import org.junit.runners.Suite.SuiteClasses;

import com.netscape.beakertests.CATestJunit;
import com.netscape.beakertests.PKITestSuite;
import com.netscape.beakertests.SampleTest1;

@RunWith(PKITestSuite.class)
@SuiteClasses({ CATestJunit.class, SampleTest1.class })
public class BeakerTestSuite {
    // Just a holder for all the test cases.

}
