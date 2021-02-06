package archer.algorithm.ecdsa;

import java.math.BigInteger;
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

public class Ecdsa {
	/**
	 * Parameters for y^2 = x^3 + a*x + b (mod = P).
	 * Base point G(x,y).
	 * */
	BigInteger P;
	BigInteger N;
	BigInteger A;
	BigInteger B;
	BigInteger Gx;
	BigInteger Gy;
	

	CLGRandom r;
	
	/**
	 * Initialize several numbers in range 0~9.
	 * */
	static final BigInteger[] NUM = {
			BigInteger.ZERO, BigInteger.ONE, new BigInteger("2"), new BigInteger("3"), new BigInteger("4"),
			new BigInteger("5"), new BigInteger("6"), new BigInteger("7"), new BigInteger("8"), new BigInteger("9")
	};
	
	protected Ecdsa(Curve curve) {
		P = curve.P;
		N = curve.N;
		A = curve.A;
		B = curve.B;
		Gx = curve.Gx;
		Gy = curve.Gy;

		r = new CLGRandom();
	}
	
	/**
	 * @param curve the Elliptic Curves.
	 * 
	 * @return instance of algorithm.
	 * */
	public static Ecdsa from(Curve curve) {
		return new Ecdsa(curve);
	}

	/**
	 * @param privKeyBytes private key content bytes.
	 * @param hashBytes hash content bytes.
	 * 
	 * @return signature string.
	 * */
	public String sign(byte[] privKeyBytes, byte[] hashBytes) {
		try {
			BigInteger priv = NumberUtil.bytesToBigInt(privKeyBytes);
			BigInteger hash = NumberUtil.bytesToBigInt(hashBytes);
			byte[] v0 = r.randomBytes(32);
			byte[] k0 = r.randomBytes(32);
			
			byte[] k1 = HashUtil.hmac(k0, concatBytes(v0, new byte[] {0}, privKeyBytes, hashBytes));
			byte[] v1 = HashUtil.hmac(k1, v0);
			byte[] k2 = HashUtil.hmac(k1, concatBytes(v1, new byte[] {1}, privKeyBytes, hashBytes));
			byte[] v2 = HashUtil.hmac(k2, v1);

			BigInteger k = new BigInteger(HashUtil.hmac(k2, v2));

			BigInteger[] p = fastMultiply(Gx,Gy,NUM[1],k);
			
			BigInteger z = inv(p[2],P);
			BigInteger r = z.pow(2).multiply(p[0]).mod(P), y = z.pow(3).multiply(p[1]).mod(P);

			BigInteger sRaw = inv(k,N).multiply(hash.add(r.multiply(priv))).mod(N);
			BigInteger s = sRaw.multiply(NUM[2]).compareTo(N) < 0?sRaw:N.subtract(sRaw);
				
			BigInteger v = y.mod(NUM[2]).xor(sRaw.multiply(NUM[2]).compareTo(N) < 0?y.mod(NUM[2]):NUM[1]);
			
			String rs = r.toString(16), ss = s.toString(16);
			if(ss.length() < 32)
				ss = '0'+ss;
			return rs+ss+'0'+v.toString(16);
		} catch(NoSuchAlgorithmException e) {
			throw new java.lang.RuntimeException(e);
		}
	}
	

	/**
	 * @param pubKeyBytes public key content bytes.
	 * @param hashBytes hash content bytes.
	 * @param sig signature content.
	 * 
	 * @return if the hash content has been falsified, return false.
	 * */
	public boolean verify(byte[] pubKeyBytes, byte[] hashBytes, String sig) {
		if(sig.length() != 130)
			throw new java.lang.RuntimeException("Invalid signature, "+sig);
		if(pubKeyBytes.length != 64)
			throw new java.lang.RuntimeException("Invalid publickKey.");
		
		BigInteger r = new BigInteger(sig.substring(0,64),16), s = new BigInteger(sig.substring(64,128),16);
		if(r.mod(N).equals(NUM[0]) || s.mod(N).equals(NUM[0]))
			return false;
		
		byte[] xBytes = new byte[32], yBytes = new byte[32];
		System.arraycopy(pubKeyBytes, 0, xBytes, 0, 32);
		System.arraycopy(pubKeyBytes, 32, yBytes, 0, 32);
		BigInteger x = NumberUtil.bytesToBigInt(xBytes), y = NumberUtil.bytesToBigInt(yBytes);
		
		BigInteger w = inv(s, N);
		BigInteger z = NumberUtil.bytesToBigInt(hashBytes);
		
		BigInteger u1 = z.multiply(w).mod(N), u2 = r.multiply(w).mod(N);
		
		BigInteger[] p = fastMultiply(Gx,Gy,NUM[1],u1);
		BigInteger pz = inv(p[2],P);
		BigInteger px = pz.pow(2).multiply(p[0]).mod(P), py = pz.pow(3).multiply(p[1]).mod(P);
		
		BigInteger[] q = fastMultiply(x,y,NUM[1],u2);
		BigInteger qz = inv(q[2],P);
		BigInteger qx = qz.pow(2).multiply(q[0]).mod(P), qy = qz.pow(3).multiply(q[1]).mod(P);
		
		BigInteger[] g = fastAdd(px, py, NUM[1], qx, qy, NUM[1]);
		BigInteger gz = inv(g[2],P);
		BigInteger gx = gz.pow(2).multiply(g[0]).mod(P);
		
		return r.equals(gx);
	}
	

	/**
	 * @param privKeyBytes private key content bytes.
	 * 
	 * @return bytes calculate public key bytes from private key bytes.
	 * */
	public byte[] privateKeyToPublicKey(byte[] privKeyBytes) {
		BigInteger priv = NumberUtil.bytesToBigInt(privKeyBytes);
		if(priv.compareTo(N) > 0)
			throw new java.lang.RuntimeException("Invalid private key.");

		BigInteger[] p = fastMultiply(Gx,Gy,NUM[1],priv);
		BigInteger z = inv(p[2],P);
		BigInteger x = z.pow(2).multiply(p[0]).mod(P), y = z.pow(3).multiply(p[1]).mod(P);
		byte[] xBs = NumberUtil.bigIntToBytes(x), yBs = NumberUtil.bigIntToBytes(y);
		byte[] pubKeyBytes = new byte[64];
		System.arraycopy(xBs, 0, pubKeyBytes, 0, xBs.length);
		System.arraycopy(yBs, 0, pubKeyBytes, 32, yBs.length);
		return pubKeyBytes;
	}

	/**
	 * @param hashBytes hash content bytes.
	 * @param sig signature content.
	 * 
	 * @return bytes calculate public key bytes from signature and hash.
	 * */
	public byte[] recoverToPublicKey(byte[] hashBytes, String sig) {
		if(sig.length() != 130)
			throw new java.lang.RuntimeException("Invalid signature, "+sig);
		BigInteger _27 = new BigInteger("27"), _34 = new BigInteger("34");
		BigInteger r = new BigInteger(sig.substring(0,64),16), s = new BigInteger(sig.substring(64,128),16);
		if(r.mod(N).equals(NUM[0]) || s.mod(N).equals(NUM[0]))
			throw new java.lang.RuntimeException("Invalid signature, "+sig);
		
		BigInteger v = new BigInteger(sig.substring(128, 130),16).add(_27);
		if(v.compareTo(_27)<0 || v.compareTo(_34)>0)
			throw new java.lang.RuntimeException("Invalid signature, "+sig);
		
		BigInteger x = r;
		BigInteger num = x.pow(3).add(x.multiply(A).add(B)).mod(P);
		
		BigInteger y = num.modPow(P.add(NUM[1]).divide(NUM[4]),P);
		if(y.mod(NUM[2]).xor(v.mod(NUM[2])).equals(NUM[0]))
			y = P.subtract(y);
		
		if(!y.pow(2).subtract(num).mod(P).equals(NUM[0]))
			throw new java.lang.RuntimeException("Invalid signature, "+sig);
		
		BigInteger z = NumberUtil.bytesToBigInt(hashBytes);
		BigInteger[] GZ = fastMultiply(Gx,Gy,NUM[1],N.subtract(z).mod(N));
		BigInteger[] XY = fastMultiply(x,y,NUM[1],s);
		
		BigInteger[] QR = fastAdd(GZ[0],GZ[1],GZ[2], XY[0],XY[1],XY[2]);
		BigInteger[] Q = fastMultiply(QR[0],QR[1],QR[2],inv(r,N));
		
		BigInteger pubZ = inv(Q[2],P);
		BigInteger left = pubZ.pow(2).multiply(Q[0]).mod(P), right = pubZ.pow(3).multiply(Q[1]).mod(P);
		
		byte[] leftBs = NumberUtil.bigIntToBytes(left), rightBs = NumberUtil.bigIntToBytes(right);
		byte[] pubBytes = new byte[leftBs.length+rightBs.length];
		System.arraycopy(leftBs, 0, pubBytes, 0, leftBs.length);
		System.arraycopy(rightBs, 0, pubBytes, leftBs.length, rightBs.length);
		return pubBytes;
	}
	
	BigInteger quickPow(BigInteger n, BigInteger m, BigInteger mod) {
		if(m.equals(NUM[1]))
			return n.mod(mod);
		BigInteger[] a = m.divideAndRemainder(NUM[2]);
		BigInteger r = quickPow(n,a[0],mod).pow(2).mod(mod);
		if(a[1].equals(NUM[0])) 
			return r;
		return n.multiply(r).mod(mod);
	}
	
	BigInteger[] fastMultiply(BigInteger a0, BigInteger a1, BigInteger a2, BigInteger n) {
		if(a1.equals(NUM[0]) || n.equals(NUM[0]))
			return new BigInteger[]{NUM[0],NUM[0],NUM[1]};
		if(n.equals(NUM[1]))
	        return new BigInteger[]{a0,a1,a2};
		if(n.signum() < 0 || n.compareTo(N) >= 0) 
			return fastMultiply(a0,a1,a2,n.mod(N));

		BigInteger[] a = fastMultiply(a0, a1, a2, n.shiftRight(1));
		BigInteger[] p = fastDouble(a[0],a[1],a[2]);
		if(n.mod(NUM[2]).equals(NUM[0])) {
			return p;
		} else if(n.mod(NUM[2]).equals(NUM[1])) {
			return fastAdd(p[0],p[1],p[2],a0,a1,a2);
		} else
			throw new java.lang.RuntimeException("Invalid BigInteger. "+n.toString(16));
	}
	
	BigInteger[] fastDouble(BigInteger a0, BigInteger a1, BigInteger a2) {
		BigInteger ysq = a1.pow(2).mod(P);
		BigInteger s = ysq.multiply(a0).multiply(NUM[4]).mod(P);
		BigInteger m = a0.pow(2).multiply(NUM[3]).add(a2.pow(4).multiply(A)).mod(P);
		
		BigInteger nx = m.pow(2).subtract(s.multiply(NUM[2])).mod(P);
		BigInteger ny = m.multiply(s.subtract(nx)).subtract(ysq.pow(2).multiply(NUM[8])).mod(P);
		BigInteger nz = a1.multiply(a2).multiply(NUM[2]).mod(P);
		return new BigInteger[] {nx, ny, nz};
	}
	
	BigInteger[] fastAdd(
			BigInteger p0, BigInteger p1, BigInteger p2,
			BigInteger q0, BigInteger q1, BigInteger q2
			) {
		BigInteger u1 = q2.pow(2).multiply(p0).mod(P);
		BigInteger u2 = p2.pow(2).multiply(q0).mod(P);
		BigInteger s1 = q2.pow(3).multiply(p1).mod(P);
		BigInteger s2 = p2.pow(3).multiply(q1).mod(P);
		if(u1.equals(u2)) {
			if(s1.equals(s2))
				return fastDouble(p0, p1, p2);
			return new BigInteger[] {NUM[0], NUM[0], NUM[1]};
		}
		BigInteger h = u2.subtract(u1), r = s2.subtract(s1);
		BigInteger h2 = h.pow(2).mod(P);
		BigInteger h3 = h2.multiply(h).mod(P);
		BigInteger u1h2 = u1.multiply(h2).mod(P);
		
		BigInteger nx = r.pow(2).subtract(h3).subtract(u1h2.multiply(NUM[2])).mod(P);
		BigInteger ny = r.multiply(u1h2.subtract(nx)).subtract(s1.multiply(h3)).mod(P);
		BigInteger nz = h.multiply(p2).multiply(q2).mod(P);

		return new BigInteger[] {nx, ny, nz};
	}
	
	static BigInteger inv(BigInteger a, BigInteger b) {
		if(a.equals(NUM[0]))
			return NUM[0];
		BigInteger lm = NUM[1], hm = NUM[0];
		BigInteger low = a.mod(b), high = b;
		
		while(low.compareTo(NUM[1]) > 0) {
			BigInteger r = high.divide(low);
			BigInteger nm = hm.subtract(lm.multiply(r)), ne = high.subtract(low.multiply(r));
			hm = lm;
			high = low;
			lm = nm;
			low = ne;
		}
		return lm.mod(b);
	}
	
	static byte[] concatBytes(byte[] ...bytes) {
		int l = 0;
		for(byte[] bs: bytes)
			l += bs.length;
		byte[] out = new byte[l];
		int s = 0;
		for(byte[] bs: bytes) {
			System.arraycopy(bs, 0, out, s, bs.length);
			s += bs.length;
		}
		return out;
	}
}
