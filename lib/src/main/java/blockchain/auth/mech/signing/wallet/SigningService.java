package blockchain.auth.mech.signing.wallet;

import blockchain.auth.mech.signing.Message;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

public class SigningService {

    public Message sign(Message message, Ed25519PrivateKeyParameters privateKey) {

        var messageBytes = message.getMessageBytes();

        var signer = new Ed25519Signer();
        signer.init(true, privateKey);
        signer.update(messageBytes, 0, messageBytes.length);
        byte[] signature = signer.generateSignature();
        return new Message(signature);
    }

    public boolean verify(Message originalMessage, Message signedMessage, Ed25519PublicKeyParameters verificationKey) {

        var messageBytes = originalMessage.getMessageBytes();

        var verifies = new Ed25519Signer();
        verifies.init(false, verificationKey);
        verifies.update(messageBytes, 0, messageBytes.length);
        return verifies.verifySignature(signedMessage.getMessageBytes());
    }

}
