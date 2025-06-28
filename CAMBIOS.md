## Versión 0.1.0

### Primera liberación pública
- Cifra en el `INSERT`
- Descifra en el `SELECT` si la llave privada está puesta
- Soporta distintas llaves públicas para cada columna usando un typmod distinto
- El catálogo de llaves públicas se queda persistente entre sesiones
- Las llaves privadas son específicas de cada sesión. 
    - Ninguna sesión tiene acceso a las llaves privadas de las otras sesiones 
    - Una vez que se cierra la conexión, todas las llaves privadas se desvanecen
    - Se puede usar la función `forget_private_key(id)` para olvidar las llaves privadas antes de terminar la conexión

### Problemas conocidos en esta versión
- El tipo `Enigma` sin typmod no se está cifrando https://git.softwarelibre.mx/SoftwareLibreMx/pg_enigma/issues/4
- `pg_dump` no está volcando la envoltura completa de Enigma https://git.softwarelibre.mx/SoftwareLibreMx/pg_enigma/issues/5
