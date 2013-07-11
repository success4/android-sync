package org.mozilla.gecko.sync.crypto;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import org.mozilla.gecko.sync.Utils;

import android.util.Log;

import junit.framework.TestCase;

// Test vectors from
// <http://tools.ietf.org/html/draft-josefsson-pbkdf2-test-vectors-06>
public class TestPBKDF2 extends TestCase {

  public final void testPBKDF2A() throws NoSuchAlgorithmException, InvalidKeySpecException, UnsupportedEncodingException {
    String  p = "password";
    String  s = "salt";
    int dkLen = 20;

    checkPBKDF2(p, s, 1, dkLen, "0c60c80f961f0e71f3a9b524af6012062fe037a6");
    checkPBKDF2(p, s, 2, dkLen, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957");
    checkPBKDF2(p, s, 4096, dkLen, "4b007901b765489abead49d926f721d065a429c1");
    
    // This test takes a long time. At least 8 minutes on my dual-core phone!
    // checkPBKDF2(p, s, 16777216, dkLen, "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984");
  }

  public final void testPBKDF2B() throws NoSuchAlgorithmException, InvalidKeySpecException, UnsupportedEncodingException {
    String  p = "passwordPASSWORDpassword";
    String  s = "saltSALTsaltSALTsaltSALTsaltSALTsalt";
    int dkLen = 25;

    checkPBKDF2(p, s, 4096, dkLen, "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038");
  }

  private void checkPBKDF2(String p, String s, int c, int dkLen,
                           final String expectedStr)
                                                    throws NoSuchAlgorithmException,
                                                    InvalidKeySpecException,
                                                    UnsupportedEncodingException {
    byte[] expected = Utils.hex2Byte(expectedStr);

    byte[] key = PBKDF2.pbkdf2SHA1(p.toCharArray(), s.getBytes("US-ASCII"), c, dkLen);
    assertEquals(expected.length, key.length);
    for (int i = 0; i < key.length; i++) {
      assertEquals(expected[i], key[i]);
    }
  }

}
