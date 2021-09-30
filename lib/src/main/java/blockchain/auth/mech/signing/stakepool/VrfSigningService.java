package blockchain.auth.mech.signing.stakepool;

import blockchain.auth.mech.signing.Message;
import com.muquit.libsodiumjna.SodiumLibrary;
import com.muquit.libsodiumjna.exceptions.SodiumLibraryException;
import org.bouncycastle.util.encoders.Hex;

import java.util.Arrays;

public class VrfSigningService {

    private static final String CIP_0022 = "cip-0022";

    public VrfSigningService() {
        this("/usr/local/lib/libsodium.dylib");
    }

    public VrfSigningService(String libsodiumPath) {
        SodiumLibrary.setLibraryPath(libsodiumPath);
    }

    public Message sign(Message message, String domain, byte[] vrfSkey) throws SodiumLibraryException {
        var prefix = String.format("%s%s", CIP_0022, domain);
        var challenge = org.bouncycastle.util.Arrays.concatenate(Hex.encode(prefix.getBytes()), message.getMessageBytes());
        var challengeHash = SodiumLibrary.cryptoBlake2bHash(Hex.decode(challenge), null);
        var signature = SodiumLibrary.cryptoVrfProve(vrfSkey, challengeHash);
        return new Message(signature);
    }

    public boolean verify(Message originalMessage, Message signedMessage, String domain, byte[] vrfVkey) throws SodiumLibraryException {
        var prefix = String.format("%s%s", CIP_0022, domain);
        var challenge = org.bouncycastle.util.Arrays.concatenate(Hex.encode(prefix.getBytes()), originalMessage.getMessageBytes());
        var challengeHash = SodiumLibrary.cryptoBlake2bHash(Hex.decode(challenge), null);
        var signatureHash = SodiumLibrary.cryptoVrfProofToHash(signedMessage.getMessageBytes());
        var verification = SodiumLibrary.cryptoVrfVerify(vrfVkey, signedMessage.getMessageBytes(), challengeHash);
        return Arrays.equals(signatureHash, verification);
    }

    public byte[] getVrfVkey(byte[] skey) throws SodiumLibraryException {
        return SodiumLibrary.cryptoVrfSkeyToVkey(skey);
    }

}
