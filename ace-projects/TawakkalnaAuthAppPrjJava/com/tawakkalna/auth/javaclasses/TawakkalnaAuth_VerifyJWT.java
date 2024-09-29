package com.tawakkalna.auth.javaclasses;

import com.ibm.broker.javacompute.MbJavaComputeNode;
import com.ibm.broker.plugin.MbElement;
import com.ibm.broker.plugin.MbException;
import com.ibm.broker.plugin.MbJSON;
import com.ibm.broker.plugin.MbMessage;
import com.ibm.broker.plugin.MbMessageAssembly;
import com.ibm.broker.plugin.MbOutputTerminal;
import com.ibm.broker.plugin.MbPolicy;
import com.ibm.broker.plugin.MbUserException;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class TawakkalnaAuth_VerifyJWT extends MbJavaComputeNode {

	public void evaluate(MbMessageAssembly inAssembly) throws MbException {
		MbOutputTerminal out = getOutputTerminal("out");
		MbMessage inMessage = inAssembly.getMessage();
		MbMessageAssembly outAssembly = null;
		try {
			MbMessage outMessage = new MbMessage();
			outAssembly = new MbMessageAssembly(inAssembly, outMessage);

			// Extracting necessary data from the message
			String token = (String) inMessage.getRootElement().getFirstElementByPath("JSON/Data/root/tawakalnaToken")
					.getValue();
			String nationalId = (String) inMessage.getRootElement().getFirstElementByPath("JSON/Data/root/nationalId")
					.getValue();
			String dateOfBirth = (String) inMessage.getRootElement().getFirstElementByPath("JSON/Data/root/dateOfBirth")
					.getValue();
			String mobileNumber = (String) inMessage.getRootElement().getFirstElementByPath("JSON/Data/root/mobileNumber")
					.getValue();
			String serviceId = (String) inMessage.getRootElement().getFirstElementByPath("JSON/Data/root/appId").getValue();

			MbMessage env = inAssembly.getGlobalEnvironment();
			env.getRootElement().createElementAsFirstChild(MbElement.TYPE_NAME_VALUE, "NationalId", nationalId);
			env.getRootElement().createElementAsFirstChild(MbElement.TYPE_NAME_VALUE, "DateOfBirth", dateOfBirth);
			env.getRootElement().createElementAsFirstChild(MbElement.TYPE_NAME_VALUE, "MobileNumber", mobileNumber);
			env.getRootElement().createElementAsFirstChild(MbElement.TYPE_NAME_VALUE, "ServiceId", serviceId);

			MbPolicy myPol = MbPolicy.getPolicy("UserDefined", "{TawakkalnaPolicies}:tawklanaPublicKeys");

			String publicKeyBase64 = myPol.getPropertyValueAsString("appId" + serviceId);

			if (publicKeyBase64 == null || publicKeyBase64 == "") {
				env.getRootElement().createElementAsFirstChild(MbElement.TYPE_NAME_VALUE, "InvalidID", "F-9006");
				throw new IllegalArgumentException("Invalid Service Id.");
			}

			PublicKey publicKey = getPublicKeyFromPKCS1(publicKeyBase64);
            Claims claims = validateToken(token, publicKey);
			
            boolean isValid = false; 
            if (claims != null) {
            	isValid = true;
			 }

            env.getRootElement().createElementAsFirstChild(MbElement.TYPE_NAME_VALUE, "isValid", isValid);

			// Populate the response with token validation status
			MbElement outRoot = outMessage.getRootElement();
			MbElement outJsonRoot = outRoot.createElementAsLastChild(MbJSON.PARSER_NAME);
			MbElement outJsonData = outJsonRoot.createElementAsLastChild(MbElement.TYPE_NAME, MbJSON.DATA_ELEMENT_NAME,
					null);
			outJsonData.createElementAsLastChild(MbElement.TYPE_NAME_VALUE, "tokenValidated", isValid);


		} catch (MbException e) {
			throw e; // Re-throw MbException to propagate errors in message flow
		} catch (RuntimeException e) {
			throw e; // Handle runtime exceptions
		} catch (Exception e) {
			// Throw a user-defined exception with meaningful error details
			throw new MbUserException(this, "evaluate()", "", "", e.toString(), null);
		}

		// Only propagate after a successful validation
		out.propagate(outAssembly);
	}
	
	public static PublicKey getPublicKeyFromPKCS1(String base64PublicKey) throws Exception {

		 byte[] pkcs1Bytes = Base64.getDecoder().decode(base64PublicKey);

	        // Manually convert PKCS#1 to PKCS#8
	        byte[] pkcs8Header = new byte[] {
	            0x30, (byte)0x82, 0x01, 0x22, // SEQUENCE header
	            0x30, 0x0D,                   // SEQUENCE header for AlgorithmIdentifier
	            0x06, 0x09,                   // OBJECT IDENTIFIER for rsaEncryption
	            0x2A, (byte)0x86, 0x48, (byte)0x86, (byte)0xF7, 0x0D, 0x01, 0x01, 0x01,
	            0x05, 0x00,                   // NULL
	            0x03, (byte)0x82, 0x01, 0x0F, // BIT STRING header
	            0x00                          // Padding byte
	        };

	        byte[] pkcs8bytes = new byte[pkcs8Header.length + pkcs1Bytes.length];
	        System.arraycopy(pkcs8Header, 0, pkcs8bytes, 0, pkcs8Header.length);
	        System.arraycopy(pkcs1Bytes, 0, pkcs8bytes, pkcs8Header.length, pkcs1Bytes.length);

	        // Decode the final PKCS#8 formatted key
	        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(pkcs8bytes);
	        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
	        return keyFactory.generatePublic(keySpec);
	}
	
    private static Claims validateToken(String token, PublicKey publicKey) {
        return Jwts.parserBuilder()
                .setSigningKey(publicKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
	
}