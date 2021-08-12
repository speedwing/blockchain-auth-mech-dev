/*
 * This Java source file was generated by the Gradle 'init' task.
 */
package blockchain.auth.mech.dev;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.ByteString;
import com.bloxbean.cardano.client.account.Account;
import com.bloxbean.cardano.client.exception.CborDeserializationException;
import com.bloxbean.cardano.client.exception.CborSerializationException;
import com.bloxbean.cardano.client.util.HexUtil;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class SigningServiceTest {

    // Standard document https://datatracker.ietf.org/doc/html/rfc8037#section-3.1.2

    @Test
    public void testBouncyCastle() throws CryptoException {


        // Test case defined in https://tools.ietf.org/html/rfc8037
        var msg = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc".getBytes(StandardCharsets.UTF_8);
        var expectedSig = "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg";

        var privateKeyBytes = Base64.getUrlDecoder().decode("nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A");
        var publicKeyBytes = Base64.getUrlDecoder().decode("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo");

        var privateKey = new Ed25519PrivateKeyParameters(privateKeyBytes, 0);
        var actualVekey = privateKey.generatePublicKey();
        var publicKey = new Ed25519PublicKeyParameters(publicKeyBytes, 0);

        System.out.println(new String(publicKey.getEncoded()));
        System.out.println(new String(actualVekey.getEncoded()));

        assertEquals(
                new String(publicKey.getEncoded()),
                new String(actualVekey.getEncoded())
        );

//        // Generate new signature
//        Signer signer = new Ed25519Signer();
//        signer.init(true, privateKey);
//        signer.update(msg, 0, msg.length);
//        byte[] signature = signer.generateSignature();
//        var actualSignature = Base64.getUrlEncoder().encodeToString(signature).replace("=", "");
//
//        System.out.printf("Expected signature: %s\n", expectedSig);
//        System.out.printf("Actual signature  : %s\n", actualSignature);
//
//        assertEquals(expectedSig, actualSignature);
//
//        var verifies = new Ed25519Signer();
//        verifies.init(false, publicKey);
//        verifies.update(msg, 0, msg.length);
//        var outcome = verifies.verifySignature(signature);
//        System.out.println(outcome);
//        assertTrue(outcome);


    }


    @Test
    public void testTwo() throws CryptoException, CborSerializationException, CborDeserializationException {
        var mnemonic = "speed length dinner home fever grunt fog garbage add clock one remain armor absent found conduct play member husband lawsuit ramp game legal target";
        var account = new Account(mnemonic);
        System.out.println(account.mnemonic());

        byte[] privateKeyBytes = account.privateKeyBytes();
        byte[] publicKeyBytes = account.publicKeyBytes();


        System.out.println(HexUtil.encodeHexString(privateKeyBytes));


        var privateKey = new Ed25519PrivateKeyParameters(privateKeyBytes, 0);
        var actualPkey = privateKey.generatePublicKey();
        var publicKey = new Ed25519PublicKeyParameters(publicKeyBytes, 0);


        System.out.println(new String(actualPkey.getEncoded()));
        System.out.println(new String(publicKey.getEncoded()));

//        var msg = "can it be pretty much everything?".getBytes(StandardCharsets.UTF_8);

//        // Generate new signature
//        Signer signer = new Ed25519Signer();
//        signer.init(true, privateKey);
//        signer.update(msg, 0, msg.length);
//        byte[] signature = signer.generateSignature();
//
//        var verifier = new Ed25519Signer();
//        verifier.init(false, publicKey);
//        signer.update(msg, 0, msg.length);
//        var result = verifier.verifySignature(signature);
//        System.out.println(result);
//        assertTrue(result);


    }


    @Test
    public void testThree() throws CborException {
        var skeyCBORHex = "582004927daa27b227b379e0a7c8bc431200dde599e76793931082c37b3ecb8a6031";
        var vkeyCBORHex = "58203b90cdc93baa2a51689e6ae747dcc9ec6e3bf8f11963bcba50036a2443c09b0b";

        var skeyBytesActual = (ByteString) CborDecoder.decode(Hex.decode(skeyCBORHex)).get(0);
        var vkeyBytesActual = (ByteString) CborDecoder.decode(Hex.decode(vkeyCBORHex)).get(0);

        // This can be used as intermediary with cbor.me
        // var skeyHex = "04927DAA27B227B379E0A7C8BC431200DDE599E76793931082C37B3ECB8A6031";
        // var vkeyHex = "3B90CDC93BAA2A51689E6AE747DCC9EC6E3BF8F11963BCBA50036A2443C09B0B";
        // var skeyBytes = Hex.decode(skeyHex);
        // var vkeyBytes = Hex.decode(vkeyHex);
        // assertArrayEquals(skeyBytes, skeyBytesActual.getBytes());
        // assertArrayEquals(vkeyBytes, vkeyBytesActual.getBytes());

        var privateKey = new Ed25519PrivateKeyParameters(skeyBytesActual.getBytes(), 0);
        var actualVekey = privateKey.generatePublicKey();
        var publicKey = new Ed25519PublicKeyParameters(vkeyBytesActual.getBytes(), 0);

        assertEquals(
                new String(publicKey.getEncoded()),
                new String(actualVekey.getEncoded())
        );

        var msg = "Cardano is the best blockchain. Sign. Gimbalabs".getBytes(StandardCharsets.UTF_8);

        // Generate new signature
        var signer = new Ed25519Signer();
        signer.init(true, privateKey);
        signer.update(msg, 0, msg.length);
        byte[] signature = signer.generateSignature();

        var verifies = new Ed25519Signer();
        verifies.init(false, publicKey);
        verifies.update(msg, 0, msg.length);
        var outcome = verifies.verifySignature(signature);
        System.out.println(outcome);
        assertTrue(outcome);

        System.out.printf("Message: %s\n", new String(msg));
        System.out.printf("Signature: %s\n", new String(signature));

    }

    @Test
    public void testFour() throws CborException {

        var skeyCBORHex = "582004927daa27b227b379e0a7c8bc431200dde599e76793931082c37b3ecb8a6031";
        var vkeyCBORHex = "58203b90cdc93baa2a51689e6ae747dcc9ec6e3bf8f11963bcba50036a2443c09b0b";

        var skeyBytesActual = (ByteString) CborDecoder.decode(Hex.decode(skeyCBORHex)).get(0);
        var vkeyBytesActual = (ByteString) CborDecoder.decode(Hex.decode(vkeyCBORHex)).get(0);

        var privateKey = new Ed25519PrivateKeyParameters(skeyBytesActual.getBytes(), 0);
        var actualVekey = privateKey.generatePublicKey();
        var publicKey = new Ed25519PublicKeyParameters(vkeyBytesActual.getBytes(), 0);

        assertEquals(
                new String(publicKey.getEncoded()),
                new String(actualVekey.getEncoded())
        );

        var msg = new Message("Cardano is the best blockchain. Sign. Gimbalabs".getBytes(StandardCharsets.UTF_8));

        var ss = new SigningService();

        var signedMessage = ss.sign(msg, privateKey);

        var outcome = ss.verify(msg, signedMessage, publicKey);

        assertTrue(outcome);

    }

    @Test
    public void testFive() throws CborException {

        var skeyCBORHex = "582004927daa27b227b379e0a7c8bc431200dde599e76793931082c37b3ecb8a6031";
        var vkeyCBORHex = "58203b90cdc93baa2a51689e6ae747dcc9ec6e3bf8f11963bcba50036a2443c09b0b";

        var skeyBytesActual = (ByteString) CborDecoder.decode(Hex.decode(skeyCBORHex)).get(0);
        var vkeyBytesActual = (ByteString) CborDecoder.decode(Hex.decode(vkeyCBORHex)).get(0);

        var privateKey = new Ed25519PrivateKeyParameters(skeyBytesActual.getBytes(), 0);
        var actualVekey = privateKey.generatePublicKey();
        var publicKey = new Ed25519PublicKeyParameters(vkeyBytesActual.getBytes(), 0);

        assertEquals(
                new String(publicKey.getEncoded()),
                new String(actualVekey.getEncoded())
        );

        var msg = new Message("ec263b59-fd3b-4ff3-b65b-d20af62cbaa2-1628785019588".getBytes(StandardCharsets.UTF_8));

        var ss = new SigningService();

        var signedMessage = ss.sign(msg, privateKey);

        System.out.println("signed message");
        System.out.println(new String(Hex.encode(signedMessage.getMessageBytes())));

        var outcome = ss.verify(msg, signedMessage, publicKey);

        assertTrue(outcome);

    }

}
