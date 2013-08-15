package com.netscape.cmscore.request;

import java.util.Vector;

import junit.framework.Test;
import junit.framework.TestSuite;

import com.netscape.certsrv.request.AgentApproval;
import com.netscape.certsrv.request.AgentApprovals;
import com.netscape.cmscore.test.CMSBaseTestCase;

public class AgentApprovalsTest extends CMSBaseTestCase {

    AgentApprovals agentApprovals;

    public AgentApprovalsTest(String name) {
        super(name);
    }

    public void cmsTestSetUp() {
        agentApprovals = new AgentApprovals();
    }

    public void cmsTestTearDown() {
    }

    public static Test suite() {
        return new TestSuite(AgentApprovalsTest.class);
    }

    public void testToFromStringVector() {
        AgentApproval approval1 = agentApprovals.addApproval("user1");
        AgentApproval approval2 = agentApprovals.addApproval("user2");
        AgentApproval approval3 = agentApprovals.addApproval(";user4;messy name");

        Vector<String> stringVector = agentApprovals.toStringVector();
        assertNotNull(stringVector);
        assertEquals(3, stringVector.size());
        assertEquals(approval1.getDate().getTime() + ";" + approval1.getUserName(),
                stringVector.get(0));
        assertEquals(approval2.getDate().getTime() + ";" + approval2.getUserName(),
                stringVector.get(1));
        assertEquals(approval3.getDate().getTime() + ";" + approval3.getUserName(),
                stringVector.get(2));

        AgentApprovals approvals = AgentApprovals.fromStringVector(stringVector);
        assertNotNull(approvals);
        assertEquals(3, approvals.size());

        AgentApproval approval = approvals.get(0);
        assertEquals(approval1.getUserName(), approval.getUserName());
        assertEquals(approval1.getDate(), approval.getDate());

        approval = approvals.get(1);
        assertEquals(approval2.getUserName(), approval.getUserName());
        assertEquals(approval2.getDate(), approval.getDate());

        approval = approvals.get(2);
        assertEquals(approval3.getUserName(), approval.getUserName());
        assertEquals(approval3.getDate(), approval.getDate());

        // test bad data
        stringVector = new Vector<String>();
        stringVector.add("foo");
        assertNull(AgentApprovals.fromStringVector(stringVector));

        stringVector = new Vector<String>();
        stringVector.add(";foo");
        assertNull(AgentApprovals.fromStringVector(stringVector));

        stringVector = new Vector<String>();
        stringVector.add("bar;foo");
        assertNull(AgentApprovals.fromStringVector(stringVector));

        stringVector = new Vector<String>();
        stringVector.add("00123b;foo");
        assertNull(AgentApprovals.fromStringVector(stringVector));

        assertNull(AgentApprovals.fromStringVector(null));
    }
}
