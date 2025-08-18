pub use sea_orm_migration::prelude::*;

mod m20250817_151638_create_users;
mod m20250817_185935_update_users;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20250817_151638_create_users::Migration),
            Box::new(m20250817_185935_update_users::Migration),
        ]
    }
}
