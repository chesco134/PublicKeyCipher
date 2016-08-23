package org.capiz.chingon;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class PublicDecipherTest {

	public static void main(String args[]) {
		if(args.length != 3){
			System.out.println("Usage: PublicDecipherTest CIPHER_AES CIPHER_FILE OUTPUT_FILE_NAME");
			System.exit(1);
		}
		try {
			PublicEncryption secure = new PublicEncryption();
			// The first argument contains the aes key.
			secure.loadKey(new File(args[0]), new File("private.der"));
			DataInputStream entrada = new DataInputStream(new FileInputStream(new File(args[1])));
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			int length;
			byte[] chunk = new byte[1024];
			while((length = entrada.read(chunk)) != -1)
				baos.write(chunk, 0, length);
			byte[] cipheredBytes = baos.toByteArray();
			baos.close();
			entrada.close();
			System.out.println("We've input " + cipheredBytes.length + " bytes.");
			ByteArrayOutputStream recuperado = new ByteArrayOutputStream();
			secure.decrypt(new ByteArrayInputStream(cipheredBytes), recuperado);
			DataOutputStream salida = new DataOutputStream(new FileOutputStream(new File(args[2])));
			salida.write(recuperado.toByteArray());
			recuperado.close();
			salida.close();
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
