package archer.algorithm.ecdsa;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * 
 * Copyright (c) 2021 Archerxy
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * 
 * @author archer
 *
 */

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

	/**
	 * @param privKey private key content bytes.
	 * @param hash hash content in bytes.
	 * 
	 * @return bytes get mystic hash bytes from private key and hash content.
	 * */
	public static byte[] hmac(byte[] privKey, byte[] hash) throws NoSuchAlgorithmException {
		byte[] priv = new byte[64];
		
		System.arraycopy(privKey, 0, priv, 0, 32);
		
		MessageDigest outer = MessageDigest.getInstance("sha-256");
		MessageDigest inner = MessageDigest.getInstance("sha-256");
		
		outer.update(translate(priv,_5C));
		inner.update(translate(priv,_36));
		inner.update(hash);
		
		outer.update(inner.digest());
		return outer.digest();
	}
}
