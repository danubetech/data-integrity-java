package com.danubetech.dataintegrity;

import com.danubetech.dataintegrity.signer.LdSignerRegistry;
import com.danubetech.dataintegrity.suites.DataIntegritySuite;
import com.danubetech.dataintegrity.suites.DataIntegritySuites;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class LdSignerRegistryTest {

	@Test
	public void testLdSignerRegistry() throws Exception {

		for (DataIntegritySuite dataIntegritySuite : DataIntegritySuites.DATA_INTEGRITY_SUITES) {
			assertEquals(LdSignerRegistry.getLdSignerByDataIntegritySuite(dataIntegritySuite).getDataIntegritySuite(), dataIntegritySuite);
		}

		for (DataIntegritySuite dataIntegritySuite : DataIntegritySuites.DATA_INTEGRITY_SUITES) {
			assertEquals(LdSignerRegistry.getLdSignerByDataIntegritySuiteTerm(dataIntegritySuite.getTerm()).getDataIntegritySuite(), dataIntegritySuite);
		}

		for (DataIntegritySuite dataIntegritySuite : DataIntegritySuites.DATA_INTEGRITY_SUITES) {
			assertEquals(LdSignerRegistry.getLdSignerByDataIntegritySuite(dataIntegritySuite).getClass(), LdSignerRegistry.getLdSignerByDataIntegritySuiteTerm(dataIntegritySuite.getTerm()).getClass());
		}
	}
}
