## Versión 0.5.0

### Cambios
- Soporte para pgrx-0.16.1
- Soporte para rpgp-0.17.0
- Se le sacó la vuelta al bug del typmod de la función `INPUT`
- Retrabajo del encabezado de Enigma, ahora indica el cifrado utilizado
- Nuevo tipo de dato `Epgp` acepta solo cifrado PGP 
- Nuevo tipo de dato `Ersa` acepta solo cifrado RSA usando OpenSSL


### Problemas conocidos
- https://git.softwarelibre.mx/SoftwareLibreMx/pg_enigma/issues/4 
- En la versión 0.5.0 se puso una restricción que forzar al uso del `ASSIGNMENT CAST` cuando el typmod es abmíguo en la función `INPUT`.

## Versión 0.4.0

### Cambios
- Soporte para rpgp-0.16.0
- Retrabajo de `Enigma`:
    - Se quitó `EnigmaMsg` y sus conversiones innecesarias. Ahora la `Enum` es `Enigma`.
    - Método `encrypt()` en `Enigma` en vez de `PubKeyMap`
    - Método `decrypt()` en `Enigma` en vez de `PrivKeyMap`
- Retrabajo de las funciones de Postgres
    - Todas las funciones de Postgres ahora regresan `Result<T,dyn Error>`
- Corrección:`CAST(Text AS Enigma)` de asignación resuelve: #39

### Problemas conocidos
- https://git.softwarelibre.mx/SoftwareLibreMx/pg_enigma/issues/4 
- En la rama `postgresql-typmod-patch` estamos trabajando en un mejor parche para Postgres Postgres que resuelva este problema.


## Versión 0.3.0

### Funcionalidad
- spec de RPM compilando en Fedora 42
- Soporte para pgrx 0.15.0
- Resiseño de la envoltura de Enigma: Nuevo encabezado de tamaño fijo
- El índice del mapa de llaves ahora es `u32`
- Pruebas de pgrx para `CAST(Enigma AS Text)`

### Problemas conocidos 
- https://git.softwarelibre.mx/SoftwareLibreMx/pg_enigma/issues/4 La rama postgresql-typmod-patch provee un parche para Postgres que resuelve este problema.

## Versión 0.2.0

### Correcciones
- Dead lock en PubKeysMap::get()
- pg_dump no volcaba la envoltura de enigma

### Funcionalidad
- Funciones SEND y RECEIVE

### Problemas conocidos 
- https://git.softwarelibre.mx/SoftwareLibreMx/pg_enigma/issues/4


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
