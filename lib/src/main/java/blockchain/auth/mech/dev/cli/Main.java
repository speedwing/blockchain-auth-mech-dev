package blockchain.auth.mech.dev.cli;

import blockchain.auth.mech.dev.Message;
import blockchain.auth.mech.dev.SigningService;
import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.model.ByteString;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.util.encoders.Hex;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.util.concurrent.Callable;

@Command(name = "signer", mixinStandardHelpOptions = true, version = "checksum 4.0",
        description = "Prints the checksum (MD5 by default) of a file to STDOUT.")
public class Main implements Callable<Integer> {

    @Parameters(index = "0", description = "The message to sign")
    private String message;

    @CommandLine.ArgGroup(exclusive = true, multiplicity = "1")
    Exclusive exclusive;

    static class Exclusive {

        @Option(names = {"-k", "--payment-skey"}, required = true, description = "Payment skey HEX", arity = "0..1")
        String signingKey;

        @Option(names = {"-f", "--payment-skey-file"}, required = true, description = "Payment skey file", arity = "0..1")
        File paymentSkeyFile;

    }


    public static void main(String[] args) {
        int exitCode = new CommandLine(new Main()).execute(args);
        System.exit(exitCode);
    }

    @Override
    public Integer call() throws Exception {

        String signingKey;

        if (exclusive.paymentSkeyFile != null) {
            var objectMapper = new ObjectMapper();
            var paymentSkey = objectMapper.readValue(exclusive.paymentSkeyFile, PaymentSkey.class);
            signingKey = paymentSkey.getCborHex();
        } else {
            signingKey = exclusive.signingKey;
        }

        var skeyBytesActual = (ByteString) new CborDecoder(new ByteArrayInputStream(Hex.decode(signingKey))).decode().get(0);
        var signService = new SigningService();
        var privateKey = new Ed25519PrivateKeyParameters(skeyBytesActual.getBytes(), 0);
        var signedMessage = signService.sign(new Message(message), privateKey);
        var publicKey = Hex.encode(privateKey.generatePublicKey().getEncoded());
        var signedText = new String(Hex.encode(signedMessage.getMessageBytes()));
        System.out.printf("public_key: %s\n", new String(publicKey));
        System.out.printf("signed_message: %s\n", signedText);
        return 0;
        
    }

}
