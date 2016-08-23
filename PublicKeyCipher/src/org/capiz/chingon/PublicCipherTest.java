package org.capiz.chingon;

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

public class PublicCipherTest {

	public static void main(String args[])
	{		
		if(args.length != 3){
			System.out.println("Usage: PublicDecipherTest CIPHER_AES_FILE_NAME INPUT_FILE OUTPUT_CIPHERED_FILE_NAME");
			System.exit(1);
		}
		try{
			PublicEncryption secure = new PublicEncryption();
			System.out.println("Hemos guardado la llave de " + secure.encodedPublicKey.length + " bytes\n");
			byte[] barr = new byte[1024];
			DataInputStream entrada = new DataInputStream(new FileInputStream(new File(args[1])));
			int length;
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			while((length = entrada.read(barr)) != -1)
				baos.write(barr, 0, length);
			byte[] cipheredBytes = baos.toByteArray();
			baos.close();
			entrada.close();
			// Following code writes the cipher data to a file named by the third argument.
			DataOutputStream salida = new DataOutputStream(new FileOutputStream(new File(args[2])));
			salida.write(cipheredBytes);
			salida.close();
		}catch(IOException e){
			e.printStackTrace();
		}catch(NoSuchAlgorithmException e){
			e.printStackTrace();
		}catch(InvalidKeyException e){
			e.printStackTrace();
		}catch(GeneralSecurityException e){
			e.printStackTrace();
		}
	}
}
