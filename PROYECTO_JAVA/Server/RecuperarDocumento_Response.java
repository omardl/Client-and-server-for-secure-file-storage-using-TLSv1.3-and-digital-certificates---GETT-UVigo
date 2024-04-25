import java.io.Serializable;

import javax.security.auth.x500.X500Principal;

public class RecuperarDocumento_Response implements Serializable {

    private static final long serialVersionUID = -6392106198310247082L;    

    private int N_Error;
    private int ID_registro;
    private X500Principal ID_Owner;
    private String DocName;
    private byte[] CipherParams;
    private byte[] CipheredSymmetricKeyPGP;
    private byte[] CipheredDocWithPGP;
    private byte[] ServerSignature;
    private byte[] ServerSignatureCertificate;

    public RecuperarDocumento_Response (int N_Error) {

        this.N_Error = N_Error;

    }

    public RecuperarDocumento_Response (int N_Error, int ID_registro, X500Principal ID_Owner, String DocName, byte [] CipherParams, byte [] CipheredSymmetricKeyPGP, byte [] CipheredDocWithPGP, byte [] ServerSignature, byte [] ServerSignatureCertificate) {

        this.N_Error = 0;
        this.ID_registro = ID_registro;
        this.ID_Owner = ID_Owner;
        this.DocName = DocName;
        this.CipherParams = CipherParams;
        this.CipheredSymmetricKeyPGP = CipheredSymmetricKeyPGP;
        this.CipheredDocWithPGP = CipheredDocWithPGP;
        this.ServerSignature = ServerSignature;
        this.ServerSignatureCertificate = ServerSignatureCertificate;

    }

    public int getN_Error() {
        return N_Error;
    }

    public int getID_registro() {
        return ID_registro;
    }

    public X500Principal getID_Owner() {
        return ID_Owner;
    }

    public String getDocName() {
        return DocName;
    }

    public byte[] getCipherParams() {
        return CipherParams;
    }

    public byte[] getCipheredSymmetricKeyPGP() {
        return CipheredSymmetricKeyPGP;
    }

    public byte[] getCipheredDocWithPGP() {
        return CipheredDocWithPGP;
    }

    public byte[] getServerSignature() {
        return ServerSignature;
    }

    public byte[] getServerSignatureCertificate() {
        return ServerSignatureCertificate;
    }
}
