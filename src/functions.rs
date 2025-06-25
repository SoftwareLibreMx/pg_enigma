use pgrx::{PgBuiltInOids,Spi};
use pgrx::datum::DatumWithOid;

// TODO:
//const TABLE_NAME: &str = "enigma_public_keys";

// TODO: move to key_map module
/// Get the public key from the keys table
pub fn get_public_key(id: i32) -> Result<Option<String>, pgrx::spi::Error> {
    // if ! exists_key_table()? { return Ok(None); }
    let query = "SELECT public_key FROM _enigma_public_keys WHERE id = $1";
    let args = unsafe { 
        [ DatumWithOid::new(id, PgBuiltInOids::INT4OID.value()) ]
    };
    Spi::connect(|client| {
        let tuple_table = client.select(query, Some(1), &args)?;
        if tuple_table.len() == 0 {
            Ok(None)
        } else {
            tuple_table.first().get_one::<String>()
        }
    })

}

/* // TODO: this function might be no longer needed
pub fn exists_key_table() -> Result<bool, pgrx::spi::Error> {
    if let Some(e) = Spi::get_one("SELECT EXISTS (
        SELECT tablename
        FROM pg_catalog.pg_tables WHERE tablename = 'enigma_public_keys'
        )")? {
        return Ok(e);
    }
    // TODO: Query should always succeed either table exists or not. 
    // This unreachable should be Err
    Ok(false)
}

TODO: extension_sql! before CREATE TYPE
// TODO: rename table to _enigma_public_keys
pub fn create_key_table() -> Result<(), pgrx::spi::Error> {
    Spi::run(
        "CREATE TABLE IF NOT EXISTS enigma_public_keys (
            id INT PRIMARY KEY,
            public_key TEXT
         )"
    )
} */

// TODO: move to key_map module
pub fn insert_public_key(id: i32, key: &str)
-> Result<Option<String>, pgrx::spi::Error> {
    // create_key_table()?;
    let args = unsafe {
        [
            DatumWithOid::new(id,  PgBuiltInOids::INT4OID.value()),
            DatumWithOid::new(key, PgBuiltInOids::TEXTOID.value()),
        ]
    };
    Spi::get_one_with_args(
        r#"INSERT INTO _enigma_public_keys(id, public_key)
           VALUES ($1, $2)
           ON CONFLICT(id)
           DO UPDATE SET public_key=$2
           RETURNING 'Public key set'"#,
         &args
    )
}

