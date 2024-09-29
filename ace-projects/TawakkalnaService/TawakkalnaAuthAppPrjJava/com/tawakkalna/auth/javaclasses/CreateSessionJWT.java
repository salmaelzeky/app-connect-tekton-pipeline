package com.tawakkalna.auth.javaclasses;

import com.ibm.broker.javacompute.MbJavaComputeNode;
import com.ibm.broker.plugin.MbElement;
import com.ibm.broker.plugin.MbException;
import com.ibm.broker.plugin.MbMessage;
import com.ibm.broker.plugin.MbMessageAssembly;
import com.ibm.broker.plugin.MbUserException;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.util.Base64;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

public class CreateSessionJWT extends MbJavaComputeNode {
	/**
	 * This method generates a JWT token based on the input data and sets the token
	 * to a Global Environment Variable.
	 * 
	 * @param inAssembly The input message assembly.
	 * @throws MbException if any error occurs during the computation.
	 */
	public void evaluate(MbMessageAssembly inAssembly) throws MbException {
		try {
			MbMessageAssembly outAssembly = null;
			// Extract input data from the message assembly using FrameworkLib
			String nationalId = inAssembly.getGlobalEnvironment().getRootElement().getFirstElementByPath("NationalId")
					.getValueAsString();
			String sessionId = inAssembly.getGlobalEnvironment().getRootElement()
					.getFirstElementByPath("Variables/StoredProcedureRs/SessionManageRs/SessionId").getValueAsString();
			String birthDate = inAssembly.getGlobalEnvironment().getRootElement().getFirstElementByPath("DateOfBirth")
					.getValueAsString();

			String issuer = "HRSD Integration";
			String subject = "Mobile Session - Social ID - Birthdate JWT Creation";

			// Generate the JWT token using the input data
			String secretKey = "217a18a8e9df0d31237fd972cb323654d91def80f94b23c6b7ef3c40febce824";
			Algorithm algorithm = Algorithm.HMAC256(secretKey);

			// Encrypt the claims using a symmetric encryption algorithm like AES
			byte[] encryptionKey = { 0x72, 0x1E, 0x53, 0x32, 0x59, 0x10, 0x64, 0x29, 0x1F, 0x5E, 0x2F, 0x6B, 0x25, 0x59,
					0x21, 0x42 }; // 16-byte encryption key
			byte[] iv = new byte[16]; // initialization vector
			SecretKeySpec keySpec = new SecretKeySpec(encryptionKey, "AES");
			IvParameterSpec ivSpec = new IvParameterSpec(iv);
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
			byte[] nationalIdBytes = cipher.doFinal(nationalId.getBytes("UTF-8"));
			byte[] sessionIdBytes = cipher.doFinal(sessionId.getBytes("UTF-8"));
			byte[] birthDateBytes = cipher.doFinal(birthDate.getBytes("UTF-8"));
			byte[] nationalIdClaimBytes = cipher.doFinal("national_id".getBytes("UTF-8"));
			byte[] sessionIdClaimBytes = cipher.doFinal("session_id".getBytes("UTF-8"));
			byte[] birthDateClaimBytes = cipher.doFinal("birth_date".getBytes("UTF-8"));
			byte[] issuerBytes = cipher.doFinal(issuer.getBytes("UTF-8"));
			byte[] subjectBytes = cipher.doFinal(subject.getBytes("UTF-8"));

			String token = JWT.create().withIssuer(Base64.getEncoder().encodeToString(issuerBytes))
					.withSubject(Base64.getEncoder().encodeToString(subjectBytes))
					// Add the encrypted claims to the token
					.withClaim(Base64.getEncoder().encodeToString(nationalIdClaimBytes),
							Base64.getEncoder().encodeToString(nationalIdBytes))
					.withClaim(Base64.getEncoder().encodeToString(sessionIdClaimBytes),
							Base64.getEncoder().encodeToString(sessionIdBytes))
					.withClaim(Base64.getEncoder().encodeToString(birthDateClaimBytes),
							Base64.getEncoder().encodeToString(birthDateBytes))
					.sign(algorithm);
			MbMessage env = inAssembly.getGlobalEnvironment();
			env.getRootElement().createElementAsFirstChild(MbElement.TYPE_NAME_VALUE, "SessionJWT", token);

			// Set the JWT token to the GLobal Environment Variables
//			inAssembly.getGlobalEnvironment().getRootElement().createElementAsFirstChild(MbElement.TYPE_NAME_VALUE,
			// "SessionJWT", token);
			if (token == null || token.isEmpty()) {
			    throw new MbUserException(outAssembly, "evaluate()", "", "", "Invalid JWT Token", null);
			}

			getOutputTerminal("out").propagate(inAssembly);


		}catch (MbException e) {
			throw e; // Re-throw MbException to propagate errors in message flow
		} catch (RuntimeException e) {
			throw e; // Handle runtime exceptions
		} catch (Exception e) {
			// Throw a user-defined exception with meaningful error details
			throw new MbUserException(this, "evaluate()", "", "", e.toString(), null);
		}
	}

}
