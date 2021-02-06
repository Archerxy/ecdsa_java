package archer.algorithm.ecdsa;

import java.util.concurrent.atomic.AtomicLong;

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

public class CLGRandom {
	public CLGRandom() {
		seed = new AtomicLong(System.nanoTime()&0x36e216d71L);
	}
	static AtomicLong seed;
	
	double crand() {
		long oldSeed = seed.get();
		long newSeed = ((0x12b9b0a5L * oldSeed + 0x1b0c88a5L)&Long.MAX_VALUE) % (0x80000000L);
		seed.compareAndSet(oldSeed, newSeed);
		return newSeed / 0x1.0p31;
	}
	
	/**
	 * @param bound the range of the random integer
	 * 
	 * @return random integer in range [0,n)
	 * */
	public int nextInt(int bound) {
		if(bound <= 0)
            throw new IllegalArgumentException("bound must be positive");
		return (int) (crand()*bound);
	}
	
	/**
	 * @return random number in range [0,1)
	 * */
	public double random() {
		return crand();
	}
	
	/**
	 * @param len the length of return byte array
	 * 
	 * @return random byte array
	 * */
	public byte[] randomBytes(int len) {
		int bound = 256, b;
		byte[] ret = new byte[len];
		for(int i = 0; i < len; ++i) {
			b = nextInt(bound);
			ret[i] = (byte) (b&0xff);
		}
		return ret;
	}
}
