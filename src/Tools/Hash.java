package Tools;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Hash {
	public static String SHA256(final String text) {
		StringBuilder strHexString = new StringBuilder();
		byte byteBuffer[] = null;
		
		if (text != null && text.length() > 0) {
			try {
				MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
				messageDigest.update(text.getBytes());
				byteBuffer = messageDigest.digest();
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
				return null;
			}
			
			for (int i=0; i<byteBuffer.length; i++) {
				String hex = Integer.toHexString(0xff & byteBuffer[i]);
				if (hex.length() == 1) strHexString.append('0');
				strHexString.append(hex);
			}
		}
		return strHexString.toString();
	}
}
