package com.netscape.certsrv.request;

import java.util.Vector;

import junit.framework.Test;
import junit.framework.TestSuite;

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
        AgentApproval approval1 = new AgentApproval("user1");
        AgentApproval approval2 = new AgentApproval("user2");
        AgentApproval approval3 = new AgentApproval(";user4;messy name");
        agentApprovals.mVector.add(approval1);
        agentApprovals.mVector.add(approval2);
        agentApprovals.mVector.add(approval3);

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
        assertEquals(3, approvals.mVector.size());

        AgentApproval approval = approvals.mVector.get(0);
        assertEquals(approval1.getUserName(), approval.getUserName());
        assertEquals(approval1.getDate(), approval.getDate());

        approval = approvals.mVector.get(1);
        assertEquals(approval2.getUserName(), approval.getUserName());
        assertEquals(approval2.getDate(), approval.getDate());

        approval = approvals.mVector.get(2);
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
