package blockchain.auth.mech.dev.cli;

import java.util.Objects;

public class CardanoKey {

    private String type;
    private String description;
    private String cborHex;

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getCborHex() {
        return cborHex;
    }

    public void setCborHex(String cborHex) {
        this.cborHex = cborHex;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CardanoKey that = (CardanoKey) o;
        return Objects.equals(type, that.type) && Objects.equals(description, that.description) && Objects.equals(cborHex, that.cborHex);
    }

    @Override
    public int hashCode() {
        return Objects.hash(type, description, cborHex);
    }

}
