/*
 * This Java source file was generated by the Gradle 'init' task.
 */
package blockchain.auth.mech.signing.stakepool;

import blockchain.auth.mech.signing.Message;
import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.ByteString;
import com.muquit.libsodiumjna.SodiumLibrary;
import com.muquit.libsodiumjna.exceptions.SodiumLibraryException;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.jcajce.provider.digest.Blake2b;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;

import java.io.ByteArrayInputStream;

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
    public void vrfVkeyFromVrfSkey() throws CborException, SodiumLibraryException {

        var skeyCbor = Hex.decode("5840adb9c97bec60189aa90d01d113e3ef405f03477d82a94f81da926c90cd46a374e0ff2371508ac339431b50af7d69cde0f120d952bb876806d3136f9a7fda4381");
        var vrfSkey = (ByteString) CborDecoder.decode(skeyCbor).get(0);

        var vkeyCbor = Hex.decode("5820e0ff2371508ac339431b50af7d69cde0f120d952bb876806d3136f9a7fda4381");
        var vrfVkey = (ByteString) CborDecoder.decode(vkeyCbor).get(0);

        var vrfSigningService = new VrfSigningService();

        var actualVrfVkey = vrfSigningService.getVrfVkey(vrfSkey.getBytes());

        Assert.assertArrayEquals(vrfVkey.getBytes(), actualVrfVkey);

    }

    @Test
    public void testVrfSigningServiceCnCli() throws CborException, SodiumLibraryException {

        var skeyCbor = Hex.decode("5840adb9c97bec60189aa90d01d113e3ef405f03477d82a94f81da926c90cd46a374e0ff2371508ac339431b50af7d69cde0f120d952bb876806d3136f9a7fda4381");
        var vrfSkey = (ByteString) CborDecoder.decode(skeyCbor).get(0);

        var vkeyCbor = Hex.decode("5820e0ff2371508ac339431b50af7d69cde0f120d952bb876806d3136f9a7fda4381");
        var vrfVkey = (ByteString) CborDecoder.decode(vkeyCbor).get(0);

        var vrfSigningService = new VrfSigningService();

        var originalMessage = new Message(Hex.encode("message".getBytes()));

        var signedMessage = vrfSigningService.sign(originalMessage, "google.com", vrfSkey.getBytes());

        var outcome = Boolean.valueOf(vrfSigningService.verify(originalMessage, signedMessage, "google.com", vrfVkey.getBytes()));

        System.out.printf("Verified? %s\n", outcome);

        Assert.assertTrue(outcome);

    }


    @Test
    public void abSigning() throws CborException, SodiumLibraryException {

        var expectedChallenge = "363336393730326433303330333233323733373436313662363536323666363137323634326536653635373465623437383230653137633866636164326438303638663133316337333736613562346638643462653134616538386330643630386133646231643365376162";

        var expectedSignature = "393b4d81cec5dbc9b937c7f507c379b780960c13a01751543b08909535567fea2000903d3fb8c9ac6438cbe05d0cf19c5ba79f7c03011654e50b36fa761605a68540c9ca01aeda46967b397f958fd104";


        var skeyCbor = Hex.decode("5840ee9c48fc2052cea8852ada1b6d1e86220b52cc70b3a327185dbd7682315ff457929802bef330af23939eea07e8d398481f66496f55a70be3fb767727057bc28e");
        var vrfSkey = (ByteString) CborDecoder.decode(skeyCbor).get(0);

//        var vkeyCbor = Hex.decode("58207d6299d211a7d6a885d82148cb9e3d496615eeb25904b560d1c84493e1aa913f");
//        var vrfVkey = (ByteString) CborDecoder.decode(vkeyCbor).get(0);
//
        var vrfSigningService = new VrfSigningService();
//
//        var actualVrfVkey = vrfSigningService.getVrfVkey(vrfSkey.getBytes());
//
//        Assert.assertArrayEquals(vrfVkey.getBytes(), actualVrfVkey);

        var c22Bytes = Hex.encode("cip-0022".getBytes());
        var domainBytes = Hex.encode("stakeboard.net".getBytes());
        var bar = "eb47820e17c8fcad2d8068f131c7376a5b4f8d4be14ae88c0d608a3db1d3e7ab";

        var prefix = Arrays.concatenate(c22Bytes, domainBytes);
        var messageBytes = Arrays.concatenate(prefix, bar.getBytes());

        var actualChallenge = Hex.toHexString(messageBytes);

        System.out.println(expectedChallenge);
        System.out.println(actualChallenge);

        Assert.assertEquals(expectedChallenge, actualChallenge);

        System.out.println("equals!");

        var blake = new Blake2b.Blake2b256();
        blake.update(Hex.decode(messageBytes));

        var digest = blake.digest();

//        blake.digest();

        System.out.println(Hex.toHexString(digest));

        var expectedDigest = "37abecf95fd99bceeb570b71c9da7ac72d7ea4ca0fcd44ff979517300d004192";
//        var expectedDigest = "7cbdfd3dad7e964008881bd30d2651339a538ae88d5fb05b30097f3b5baadab4";


        var signature = SodiumLibrary.cryptoVrfProve(vrfSkey.getBytes(), messageBytes);

        System.out.println(new String(Hex.encode(signature)));

    }

    @Test
    public void testCnCli() throws CborException, SodiumLibraryException {

        var expectedChallenge = "363336393730326433303330333233323733373436313662363536323666363137323634326536653635373465623437383230653137633866636164326438303638663133316337333736613562346638643462653134616538386330643630386133646231643365376162";
        var expectedSignature = "393b4d81cec5dbc9b937c7f507c379b780960c13a01751543b08909535567fea2000903d3fb8c9ac6438cbe05d0cf19c5ba79f7c03011654e50b36fa761605a68540c9ca01aeda46967b397f958fd104";

        var skeyCbor = Hex.decode("5840ee9c48fc2052cea8852ada1b6d1e86220b52cc70b3a327185dbd7682315ff457929802bef330af23939eea07e8d398481f66496f55a70be3fb767727057bc28e");
        var vrfSkey = (ByteString) CborDecoder.decode(skeyCbor).get(0);

//
        var vrfSigningService = new VrfSigningService();
//
        var c22Bytes = Hex.encode("cip-0022".getBytes());
        var domainBytes = Hex.encode("stakeboard.net".getBytes());
        var nonce = "eb47820e17c8fcad2d8068f131c7376a5b4f8d4be14ae88c0d608a3db1d3e7ab";

        var prefix = Arrays.concatenate(c22Bytes, domainBytes);
        var messageBytes = Arrays.concatenate(prefix, nonce.getBytes());

        var actualChallenge = Hex.toHexString(messageBytes);

        System.out.println(expectedChallenge);
        System.out.println(actualChallenge);

        Assert.assertEquals(expectedChallenge, actualChallenge);

        System.out.println("equals!");

        var blake = new Blake2b.Blake2b256();
        blake.update(Hex.decode(messageBytes));
        var digest = blake.digest();
        var digestString = Hex.toHexString(digest);

        System.out.println(digestString);

        Assert.assertEquals("37abecf95fd99bceeb570b71c9da7ac72d7ea4ca0fcd44ff979517300d004192", digestString);

        var signature = SodiumLibrary.cryptoVrfProve(vrfSkey.getBytes(), digest);

        Assert.assertEquals(expectedSignature, Hex.toHexString(signature));

        var signatore2 = vrfSigningService.sign(new Message(nonce), "stakeboard.net", vrfSkey.getBytes());

        Assert.assertEquals(expectedSignature, Hex.toHexString(signatore2.getMessageBytes()));

    }

    @Test
    public void testHashVrfVkey() throws CborException, SodiumLibraryException {

        var vrfSigningService = new VrfSigningService();

        var expectedVrfKeyHash = "7ca5cff9416b219cf71df65e78dada646a12ff04938beb04e3c9d7891ac2f055";

        var vrfVkeyBytes = (ByteString) new CborDecoder(new ByteArrayInputStream(Hex.decode("58207d6299d211a7d6a885d82148cb9e3d496615eeb25904b560d1c84493e1aa913f"))).decode().get(0);

        var hashedVrfVKeyBytes = SodiumLibrary.cryptoBlake2bHash(vrfVkeyBytes.getBytes(), null);

        Assert.assertEquals(Hex.toHexString(hashedVrfVKeyBytes), expectedVrfKeyHash);

    }

}
