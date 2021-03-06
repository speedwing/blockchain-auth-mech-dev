/*
 * This Java source file was generated by the Gradle 'init' task.
 */
package blockchain.auth.mech.signing;

import org.bouncycastle.util.encoders.Hex;

import java.util.Random;

public class RandomStringGeneration {

    private final Random random = new Random();

    public String createRandomString() {
        var bytes = new byte[32];
        random.nextBytes(bytes);
        return Hex.toHexString(bytes);
    }

}
