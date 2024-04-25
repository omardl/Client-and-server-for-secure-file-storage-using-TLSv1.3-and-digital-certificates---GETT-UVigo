# Cliente y servidor para el almacenamiento seguro de archivos mediante protocolo TLSv1.3 y certificados digitales

El usuario que utilice el cliente podrá enviar cualquier tipo de archivo conectándose al servidor mediante TLSv1.3. Para ello, contarán con certificados SSL/TLS y certificados de firma que serán expedidos por una jerarquía de autoridades de certificación creadas para ello. Ésto permitirá la auteticación cliente-servidor, el establecimiento de una conexión segura y la integridad de los datos.

El servidor encriptará y almacenará los archivos, firmándolos para garantizar su integridad.

El cliente tendrá la opción de recuperar los archivos mediante un identificador proporcionado por el servidor tras su almacenamiento. 

### Proyecto desarrollado para la asignatura de "Seguridad" del Grado en Ingeniería de Tecnologías de Telecomunicación de la UVigo.

### Autor - Omar Delgado López