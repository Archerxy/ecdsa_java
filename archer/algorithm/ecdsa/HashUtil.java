package archer.algorithm.ecdsa;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashUtil {
	static final int[] _5C = new int[256];
	
	static final int[] _36 = new int[256];
	
	static {
		for(int i = 0; i < 256; ++i) {
			_5C[i] = i^0x5c;
			_36[i] = i^0x36;
		}
	}
	
	static byte[] translate(byte[] bs, int[] trans) {
		byte[] out = new byte[bs.length];
		for(int i = 0; i < bs.length; ++i) {
			int k = bs[i];
			if(k < 0)
				k = k+256;
			out[i] = (byte)trans[k];
		}
		return out;
	}
	
	public static byte[] hmac(byte[] privKey, byte[] hash) throws NoSuchAlgorithmException, CloneNotSupportedException {
		byte[] priv = new byte[64];
		
		System.arraycopy(privKey, 0, priv, 0, 32);
		
		MessageDigest outer = MessageDigest.getInstance("sha-256");
		MessageDigest inner = MessageDigest.getInstance("sha-256");
		
		outer.update(translate(priv,_5C));
		inner.update(translate(priv,_36));
		inner.update(hash);
		
		MessageDigest h = (MessageDigest) outer.clone();
		h.update(inner.digest());
		return h.digest();
	}
}
