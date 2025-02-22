package com.danubetech.dataintegrity;

import com.danubetech.dataintegrity.suites.DataIntegritySuite;
import com.danubetech.dataintegrity.suites.DataIntegritySuites;
import com.danubetech.dataintegrity.verifier.LdVerifierRegistry;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class LdVerifierRegistryTest {

	@Test
	public void testLdVerifierRegistry() throws Exception {

		for (DataIntegritySuite dataIntegritySuite : DataIntegritySuites.DATA_INTEGRITY_SUITES) {
			assertEquals(LdVerifierRegistry.getLdVerifierByDataIntegritySuite(dataIntegritySuite).getDataIntegritySuite(), dataIntegritySuite);
		}

		for (DataIntegritySuite dataIntegritySuite : DataIntegritySuites.DATA_INTEGRITY_SUITES) {
			assertEquals(LdVerifierRegistry.getLdVerifierByDataIntegritySuiteTerm(dataIntegritySuite.getTerm()).getDataIntegritySuite(), dataIntegritySuite);
		}

		for (DataIntegritySuite dataIntegritySuite : DataIntegritySuites.DATA_INTEGRITY_SUITES) {
			assertEquals(LdVerifierRegistry.getLdVerifierByDataIntegritySuite(dataIntegritySuite).getClass(), LdVerifierRegistry.getLdVerifierByDataIntegritySuiteTerm(dataIntegritySuite.getTerm()).getClass());
		}
	}
}
