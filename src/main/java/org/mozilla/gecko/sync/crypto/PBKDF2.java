/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.gecko.sync.crypto;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class PBKDF2 {
  public static byte[] pbkdf2SHA1(char[] password, byte[] salt, int c, int dkLen) throws NoSuchAlgorithmException, InvalidKeySpecException {
    // Won't work on API level 8.
    SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
    PBEKeySpec keySpec = new PBEKeySpec(password, salt, c, dkLen * 8);
    SecretKey key = factory.generateSecret(keySpec);
    return key.getEncoded();
  }
}
