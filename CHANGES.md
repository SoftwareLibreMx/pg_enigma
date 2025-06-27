### version 0.1.0

### First public release
- Encrypts on `INSERT`
- Decrypts on `SELECT` if private key is set
- Supports different public keys for each column by using different typmod
- Public keys catalog remains persistent between sessions
- Private keys are set sesion-specific. 
    - Different sessions have no access to other sessions' private keys
    - Once the connection closes, all private keys are vanished
    - Function `forget_private_key(id)` can be used to forget a private key before connection closes

### Known issues in this release
- Type `Enigma` without typmod is not encrypting https://git.softwarelibre.mx/SoftwareLibreMx/pg_enigma/issues/4
- `pg_dump` is not dumping Enigma envelope https://git.softwarelibre.mx/SoftwareLibreMx/pg_enigma/issues/5
