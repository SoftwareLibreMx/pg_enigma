SECURITY CONSIDERATIONS
========================

The following are recommendations to get the most security out of pg_enigma.
Keep in mind that there are other attack vectors unrelated to pg_enigma which
are not described here. For example, pg_enigma cannot protect non-pg_enigma
copies of the decrypted data, or from stolen private key backup copies.


Use encrypted connections to the database
-----------------------------------------

Always use a process-to-process encrypted channel to the database, like a
recent version of TLS. Otherwise, the server and client might expose private
private keys and decrypted data by transmitting it in unencrypted form over the
wire.


Load the private key the least possible amount of time
------------------------------------------------------

Add the private key right before needing the data and remove the private key as
soon as the data has been read, even if it can be needed again later.
Otherwise, in-band attacks can occur, like SQL injections. 

Treat data retrieval as an atomic procedure:

1. Load the private key.
2. Read / use the data as needed.
3. Remove the private key immediately as the procedure is done.

Remember that the private key is present in memory in the server in unencrypted
form during this time. Although removing the private key does not guarantee
that the private key has been removed from memory (as it still may be present
in cached or swapped copies of memory pages) not removing it, *guarantees* that
the private key will be present in some location in memory and it makes it
easier to be propagated and misused.


Keep track of the needed maintenance procedures
-----------------------------------------------

If the private key is lost in any way, *encrypted data will be unrecoverable*.
Examples:

1. The private key files are deleted and there are no backup copies.
2. The private key has an expiration date and it is in the past. Modifying
   system time might be a workaround but this may impact other aspects of the
   system.
3. The private key is passphrase-protected and the password is lost or
   forgotten.
4. Whoever maintains the private key or its credentials stops participating in the
   organization and no succession plan was prepared.

Avoid this by setting good security practices within the organization, such as,
among others:

1. Backup the private key under a secure human protocol.
2. Rotate the keys as needed. Data needs to be reencrypted.
3. Monitor expiration dates.
4. Backup the private key password under a secure human protocol.
5. Prepare succession plans for private key stakeholders.
