package blockchain.auth.mech;

import blockchain.auth.mech.signing.RandomStringGeneration;
import org.junit.Assert;
import org.junit.Test;

import java.util.Date;
import java.util.UUID;

public class RandomStringGenerationTest {

    @Test
    public void ensureRandomStringContainsUUIDandRecentTimestamp() {
        var randomString = new RandomStringGeneration().createRandomString();

        // Should throw exception if parsing doesn't work
        UUID.fromString(randomString.substring(0, randomString.lastIndexOf("-")));
        var instant = Long.valueOf(randomString.substring(randomString.lastIndexOf("-") + 1));

        // Simple test to check that the timestamp is "recent"
        Assert.assertTrue((new Date().getTime() - instant) < 5000L);

    }

}