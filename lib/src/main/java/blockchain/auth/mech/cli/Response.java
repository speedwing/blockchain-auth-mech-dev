package blockchain.auth.mech.cli;

import java.util.Objects;

public class Response {

    private String signedMessage;

    private String publicKey;

    public Response(String signedMessage, String publicKey) {
        this.signedMessage = signedMessage;
        this.publicKey = publicKey;
    }

    public String getSignedMessage() {
        return signedMessage;
    }

    public String getPublicKey() {
        return publicKey;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Response response = (Response) o;
        return Objects.equals(signedMessage, response.signedMessage) && Objects.equals(publicKey, response.publicKey);
    }

    @Override
    public int hashCode() {
        return Objects.hash(signedMessage, publicKey);
    }

}
