use pgrx::{IntoDatum,PgBuiltInOids,Spi};

// TODO:
//const TABLE_NAME: &str = "enigma_public_keys";

/// Get the public key from the keys table
pub fn get_public_key(id: i32) -> Result<Option<String>, pgrx::spi::Error> {
    if ! exists_key_table()? { return Ok(None); }
    let query = "SELECT public_key FROM enigma_public_keys WHERE id = $1";
    let args = vec![ (PgBuiltInOids::INT4OID.oid(), id.into_datum()) ];
    Spi::connect(|mut client| {
        let tuple_table = client.update(query, Some(1), Some(args))?;
        if tuple_table.len() == 0 {
            Ok(None)
        } else {
            tuple_table.first().get_one::<String>()
        }
    })

}

pub fn exists_key_table() -> Result<bool, pgrx::spi::Error> {
    if let Some(e) = Spi::get_one("SELECT EXISTS (
        SELECT tablename
        FROM pg_catalog.pg_tables WHERE tablename = 'enigma_public_keys'
        )")? {
        return Ok(e);
    }
    Ok(false)
}


pub fn create_key_table() -> Result<(), pgrx::spi::Error> {
    Spi::run(
        "CREATE TABLE IF NOT EXISTS enigma_public_keys (
            id INT PRIMARY KEY,
            public_key TEXT
         )"
    )
}

pub fn insert_public_key(id: i32, key: &str)
-> Result<Option<String>, pgrx::spi::Error> {
    create_key_table()?;
    Spi::get_one_with_args(
        r#"INSERT INTO enigma_public_keys(id, public_key)
           VALUES ($1, $2)
           ON CONFLICT(id)
           DO UPDATE SET public_key=$2
           RETURNING 'Public key set'"#,
        vec![
            (PgBuiltInOids::INT4OID.oid(), id.into_datum()),
            (PgBuiltInOids::TEXTOID.oid(), key.into_datum())
        ],
    )
}

