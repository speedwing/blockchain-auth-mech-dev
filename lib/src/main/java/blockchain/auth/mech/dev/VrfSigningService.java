package blockchain.auth.mech.dev;

import com.muquit.libsodiumjna.SodiumLibrary;
import com.muquit.libsodiumjna.exceptions.SodiumLibraryException;

import java.util.Arrays;

public class VrfSigningService {

    public VrfSigningService() {
        SodiumLibrary.setLibraryPath("/usr/local/lib/libsodium.dylib");
    }

    public Message sign(Message message, byte[] vrfSkey) throws SodiumLibraryException {
        var challenge = SodiumLibrary.cryptoBlake2bHash(message.getMessageBytes(), null);
        var signature = SodiumLibrary.cryptoVrfProve(vrfSkey, challenge);
        return new Message(signature);
    }

    public boolean verify(Message originalMessage, Message signedMessage, byte[] vrfVkey) throws SodiumLibraryException {
        var signatureHash = SodiumLibrary.cryptoVrfProofToHash(signedMessage.getMessageBytes());
        var challenge = SodiumLibrary.cryptoBlake2bHash(originalMessage.getMessageBytes(), null);
        var verification = SodiumLibrary.cryptoVrfVerify(vrfVkey, signedMessage.getMessageBytes(), challenge);
        return Arrays.equals(signatureHash, verification);
    }

    public byte[] getVrfVkey(byte[] skey) throws SodiumLibraryException {
        return SodiumLibrary.cryptoVrfSkeyToVkey(skey);
    }

}
