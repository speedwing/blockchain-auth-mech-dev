package blockchain.auth.mech.cli;

import blockchain.auth.mech.signing.stakepool.VrfSigningService;
import blockchain.auth.mech.signing.Message;
import blockchain.auth.mech.signing.wallet.SigningService;
import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.CborException;
import co.nstant.in.cbor.model.ByteString;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.muquit.libsodiumjna.exceptions.SodiumLibraryException;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.util.encoders.Hex;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.util.concurrent.Callable;

@Command(name = "signer", mixinStandardHelpOptions = true, version = "checksum 4.0",
        description = "Prints the checksum (MD5 by default) of a file to STDOUT.")
public class Main implements Callable<Integer> {

    @Parameters(index = "0", description = "The message to sign")
    private String message;

    @CommandLine.ArgGroup(exclusive = true, multiplicity = "1")
    Exclusive exclusive;

    static class Exclusive {

        @Option(names = {"--payment-skey"}, required = true, description = "Payment skey HEX", arity = "0..1")
        String paymentSkey;

        @Option(names = {"--payment-skey-file"}, required = true, description = "Payment skey file", arity = "0..1")
        File paymentSkeyFile;

        @Option(names = {"--vrf-skey"}, required = true, description = "VRF skey HEX", arity = "0..1")
        String vrfSkey;

        @Option(names = {"--vrf-skey-file"}, required = true, description = "VRF skey file", arity = "0..1")
        File vrfSkeyFile;

    }

    @Option(names = {"--domain"}, required = true, description = "domain for the vrf verification", arity = "0..1")
    String domain;

    public static void main(String[] args) {
        int exitCode = new CommandLine(new Main()).execute(args);
        System.exit(exitCode);
    }

    @Override
    public Integer call() throws Exception {

        Response response;
        String keyType;

        if (exclusive.paymentSkeyFile != null) {
            response = signWithPaymentSkeyFile();
            keyType = "payment";
        } else if (exclusive.paymentSkey != null) {
            response = signWithPaymentKey();
            keyType = "payment";
        } else if (exclusive.vrfSkey != null) {
            response = signWithVrfSkey();
            keyType = "vrf";
        } else {
            response = signWithVrfSkeyFile();
            keyType = "vrf";
        }

        System.out.printf("public_key: %s\n", response.getPublicKey());
        System.out.printf("signed_message: %s\n", response.getSignedMessage());
        System.out.println();
        System.out.printf("curl -X POST -H 'Content-Type: application/json' -d'{\"message\": \"%s\", \"signed_message\": \"%s\", \"public_key\": \"%s\", \"signature_type\": \"%s\"}' http://localhost:9000/auth\n", message, response.getSignedMessage(), response.getPublicKey(), keyType);

        return 0;

    }

    private Response signWithVrfSkeyFile() throws CborException, SodiumLibraryException, IOException {
        var objectMapper = new ObjectMapper();
        var paymentSkey = objectMapper.readValue(exclusive.vrfSkeyFile, CardanoKey.class);
        var signingKey = paymentSkey.getCborHex();
        return signWithVrfSkey(signingKey);
    }

    private Response signWithVrfSkey() throws SodiumLibraryException, CborException {
        return signWithVrfSkey(exclusive.vrfSkey);
    }

    private Response signWithVrfSkey(String vrfSkey) throws SodiumLibraryException, CborException {
        var vrfSkeyBytes = (ByteString) new CborDecoder(new ByteArrayInputStream(Hex.decode(vrfSkey))).decode().get(0);
        var vrfSigningService = new VrfSigningService();
        var signedMessage = vrfSigningService.sign(new Message(message), domain, vrfSkeyBytes.getBytes());
        var publicKey = new String(Hex.encode(vrfSigningService.getVrfVkey(vrfSkeyBytes.getBytes())));
        var signedText = new String(Hex.encode(signedMessage.getMessageBytes()));
        return new Response(signedText, publicKey);
    }

    private Response signWithPaymentSkeyFile() throws IOException, CborException {
        var objectMapper = new ObjectMapper();
        var paymentSkey = objectMapper.readValue(exclusive.paymentSkeyFile, CardanoKey.class);
        var signingKey = paymentSkey.getCborHex();
        return signWithPaymentKey(signingKey);
    }

    private Response signWithPaymentKey() throws CborException {
        return signWithPaymentKey(exclusive.paymentSkey);
    }

    private Response signWithPaymentKey(String paymentSkey) throws CborException {
        var skeyBytesActual = (ByteString) new CborDecoder(new ByteArrayInputStream(Hex.decode(paymentSkey))).decode().get(0);
        var signService = new SigningService();
        var privateKey = new Ed25519PrivateKeyParameters(skeyBytesActual.getBytes(), 0);
        var signedMessage = signService.sign(new Message(message), privateKey);
        var publicKey = new String(Hex.encode(privateKey.generatePublicKey().getEncoded()));
        var signedText = new String(Hex.encode(signedMessage.getMessageBytes()));
        return new Response(signedText, publicKey);
    }

}
