package blockchain.auth.mech.dev;

import co.nstant.in.cbor.CborDecoder;
import co.nstant.in.cbor.model.ByteString;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.util.encoders.Hex;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.util.concurrent.Callable;

@Command(name = "signer", mixinStandardHelpOptions = true, version = "checksum 4.0",
        description = "Prints the checksum (MD5 by default) of a file to STDOUT.")
public class Main implements Callable<Integer> {

    @Parameters(index = "0", description = "The message to sign")
    private String message;

    @Option(names = {"-k", "--payment-skey"}, description = "Payment skey HEX")
    private String signingKey;

    public static void main(String[] args) {
        int exitCode = new CommandLine(new Main()).execute(args);
        System.exit(exitCode);
    }

    public static void main1(String[] args) {

        var message = args[0];
        var privateKeyHex = args[1];

        var privateKeyBytes = Hex.decode(privateKeyHex);

        var signService = new SigningService();
        var signedText = signService.sign(new Message(message), new Ed25519PrivateKeyParameters(privateKeyBytes, 0));

        System.out.println(new String(Hex.encode(signedText.getMessageBytes())));

    }

    @Override
    public Integer call() throws Exception {
        var skeyBytesActual = (ByteString) CborDecoder.decode(Hex.decode(signingKey)).get(0);
        var signService = new SigningService();
        var signedText = signService.sign(new Message(message), new Ed25519PrivateKeyParameters(skeyBytesActual.getBytes(), 0));
        System.out.println(new String(Hex.encode(signedText.getMessageBytes())));
        return 0;
    }
}
