/*
 * This Java source file was generated by the Gradle 'init' task.
 */
package blockchain.auth.mech.dev;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.ByteString;
import com.muquit.libsodiumjna.SodiumLibrary;
import com.muquit.libsodiumjna.exceptions.SodiumLibraryException;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;

public class VrfSigningServiceTest {

//    https://github.com/cardano-foundation/CIPs/blob/ba4c18f7d21c20493b4f2583836bb367385f2b61/CIP-0022/CIP-0022.md

    @Test
    public void testVrfValidation() throws CryptoException, CborException, SodiumLibraryException {

        var skeyCbor = Hex.decode("5840adb9c97bec60189aa90d01d113e3ef405f03477d82a94f81da926c90cd46a374e0ff2371508ac339431b50af7d69cde0f120d952bb876806d3136f9a7fda4381");
        var vrfSkey = (ByteString) CborDecoder.decode(skeyCbor).get(0);

        var vkeyCbor = Hex.decode("5820e0ff2371508ac339431b50af7d69cde0f120d952bb876806d3136f9a7fda4381");
        var vrfVkey = (ByteString) CborDecoder.decode(vkeyCbor).get(0);


        // Client side, construct and sign the challenge
        var challengeSeed = "message".getBytes();
        SodiumLibrary.setLibraryPath("/usr/local/lib/libsodium.dylib");
        var challenge = SodiumLibrary.cryptoBlake2bHash(challengeSeed, null);
        System.out.printf("challenge: %s\n", new String(Hex.encode(challenge)));

        var signature = SodiumLibrary.cryptoVrfProve(vrfSkey.getBytes(), challenge);
        System.out.printf("signature: %s\n", new String(Hex.encode(signature)));


//        val challenge = SodiumLibrary.cryptoBlake2bHash(challengeSeed, null)
//
//// Get the vkeyHash for a pool from the "query pool-params" cardano-cli command
//// This comes from the pool's registration certificate on the chain.
//        val vkeyHash = "f58bf0111f8e9b233c2dcbb72b5ad400330cf260c6fb556eb30cefd387e5364c".hexToByteArray()
//
//// Verify that the vkey from the latest minted block on the blockchain (or the client supplied if they
//// haven't yet minted a block) is the same as the one on-chain in the pool's registration certificate
//        val vkeyHashVerify = SodiumLibrary.cryptoBlake2bHash(vrfVkey, null)
//        assertThat(vkeyHash).isEqualTo(vkeyHashVerify)

// Verify that the signature is a valid format. This will fail if the signature is mal-formed
        var signatureHash = SodiumLibrary.cryptoVrfProofToHash(signature);
        System.out.printf("signatureHash: %s\n", new String(Hex.encode(signatureHash)));

// Verify that the signature matches
        var verification = SodiumLibrary.cryptoVrfVerify(vrfVkey.getBytes(), signature, challenge);
        System.out.printf("verification: %s\n", new String(Hex.encode(verification)));

        System.out.println("Verify signed message");
        if (new String(Hex.encode(signatureHash)).endsWith(new String(Hex.encode(verification)))) {
            System.out.println("All good");
        } else {
            System.out.println("Signature not matching");
        }

    }


    @Test
    public void testVrfSigningService() throws CborException, SodiumLibraryException {

        var skeyCbor = Hex.decode("5840adb9c97bec60189aa90d01d113e3ef405f03477d82a94f81da926c90cd46a374e0ff2371508ac339431b50af7d69cde0f120d952bb876806d3136f9a7fda4381");
        var vrfSkey = (ByteString) CborDecoder.decode(skeyCbor).get(0);

        var vkeyCbor = Hex.decode("5820e0ff2371508ac339431b50af7d69cde0f120d952bb876806d3136f9a7fda4381");
        var vrfVkey = (ByteString) CborDecoder.decode(vkeyCbor).get(0);

        var vrfSigningService = new VrfSigningService();

        var originalMessage = new Message("message");

        var signedMessage = vrfSigningService.sign(originalMessage, vrfSkey.getBytes());

        var outcome = Boolean.valueOf(vrfSigningService.verify(originalMessage, signedMessage, vrfVkey.getBytes()));

        System.out.printf("Verified? %s\n", outcome);

        Assert.assertTrue(outcome);

    }

}
