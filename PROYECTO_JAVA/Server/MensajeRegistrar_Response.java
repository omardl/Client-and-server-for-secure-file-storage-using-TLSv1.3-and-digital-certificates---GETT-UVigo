import java.io.Serializable;

import javax.security.auth.x500.X500Principal;

public class MensajeRegistrar_Response implements Serializable{

    private static final long serialVersionUID = -6392106198310247082L;

    private int N_Error;
    private int ID_registro;
    private X500Principal ID_propietario;
    private byte[] firma_registrador;
    private byte[] cert_firma;


    public MensajeRegistrar_Response(int N_Error, int ID_registro, X500Principal ID_propietario, byte[] firma_registrador, byte[] cert_firma) {

        this.N_Error = 0;
        this.ID_registro = ID_registro;
        this.ID_propietario = ID_propietario;
        this.firma_registrador = firma_registrador;
        this.cert_firma = cert_firma;

    }

    public MensajeRegistrar_Response(int N_Error) {
        
        this.N_Error = N_Error;

    }

    public int getN_Error() {

        return this.N_Error;
    
    }

    public int getID_registro() {

        return this.ID_registro;

    }

    public X500Principal getID_propietario() {

        return this.ID_propietario;

    }
    
    public byte[] getFirma_Registrador() {
        
        return this.firma_registrador;

    }

    public byte[] getCert_firma() {

        return this.cert_firma;
        
    }
}