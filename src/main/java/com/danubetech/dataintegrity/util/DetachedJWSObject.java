package com.danubetech.dataintegrity.util;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.util.Base64URL;

import java.text.ParseException;

public class DetachedJWSObject extends JWSObject {

	private final Base64URL parsedSignature;

	public DetachedJWSObject(JWSHeader jwsHeader, Payload payload, Base64URL parsedSignature) throws ParseException {
		super(jwsHeader, payload);
		this.parsedSignature = parsedSignature;
	}

	public static DetachedJWSObject parse(String string, Payload payload) throws ParseException {
		JWSObject detachedJwsObject = JWSObject.parse(string);
		return new DetachedJWSObject(detachedJwsObject.getHeader(), payload, detachedJwsObject.getSignature());
	}


	@Override
	public State getState() {
		State state = super.getState();
		if (state == State.UNSIGNED) return State.SIGNED;

		return state;
	}

	public Base64URL getParsedSignature() {
		return this.parsedSignature;
	}
}
