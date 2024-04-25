import java.io.Serializable;

public class RecuperarDocumento_Request implements Serializable{
    
    private static final long serialVersionUID = -6392106198310247082L;

    private byte [] ClientAuthenticationCertificate;
    private int ID_registro;
    
    public RecuperarDocumento_Request(byte[] ClientAuthenticationCertificate, int ID_registro) {

        this.ClientAuthenticationCertificate = ClientAuthenticationCertificate;
        this.ID_registro = ID_registro;

    }

    public byte[] getClientAuthenticationCertificate() {
        return ClientAuthenticationCertificate;
    }

    public int getID_registro() {
        return ID_registro;
    }
        
}
