use rusqlite::{Connection, Statement};

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ThreatDatabase {
    pub name: String,
    pub md5hash: String,
    pub sha256hash: String,
}

impl ThreatDatabase {
    pub fn query_db(conn: &Connection) -> anyhow::Result<()> {
        let statement = conn.prepare("SELECT * FROM default_db")?;
        let mut stmt: Statement = statement;
        let ioc_iter = stmt.query_map([], |row| {
            let value = ThreatDatabase {
                name: row.get(1)?,
                md5hash: row.get(0)?,
                sha256hash: row.get(3)?,
            };
            Result::Ok(value)
        })?;

        for ioc in ioc_iter {
            println!("{:?}", ioc?);
        }
        Ok(())
    }

    pub fn install(
        url: &str,
        spire_dir: &std::path::Path,
        public_key: &str,
    ) -> anyhow::Result<crate::core::updates::InstalledFeed> {
        crate::core::updates::install(url, spire_dir, public_key)
    }
}
