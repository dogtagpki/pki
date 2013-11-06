package com.netscape.beakertests;

import static org.junit.Assert.*;

import org.junit.Test;

public class SampleTest1 extends PKIJUnitTest{
	@Test
	public void sampleTest() {
		assertEquals("a", "a");
		assertNotNull("Should not be null", null);
	}
}
