package blockchain.auth.mech.dev;

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.util.encoders.Hex;

public class Main {

    public static void main(String[] args) {

        var message = args[0];
        var privateKeyHex = args[1];

        var privateKeyBytes = Hex.decode(privateKeyHex);

        var signService = new SigningService();
        var signedText = signService.sign(new Message(message), new Ed25519PrivateKeyParameters(privateKeyBytes, 0));

        System.out.println(new String(Hex.encode(signedText.getMessageBytes())));

    }

}
