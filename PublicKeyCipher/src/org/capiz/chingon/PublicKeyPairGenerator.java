package org.capiz.chingon;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class PublicKeyPairGenerator {

	public static void main(String args[]) {
		try {
			PublicEncryption secure = new PublicEncryption();
			// to encrypt a file
			secure.makeKey();
			// The first argument indicates the name of the public key. The
			// output der file is named "public" and contains the aes key.
			secure.saveKey(new File(args[0]), new File("public.der"));
		} catch (IOException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}
	}
}
