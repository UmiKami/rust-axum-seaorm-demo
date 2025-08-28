use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {

        manager
            .create_table(
                Table::create()
                    .table(OAuthAccounts::Table)
                    .if_not_exists()
                    .col(pk_auto(OAuthAccounts::Id))
                    .col(string(OAuthAccounts::Provider))
                    .col(string(OAuthAccounts::ProviderAccountId))
                    .col(string_null(OAuthAccounts::AccessToken))
                    .col(string_null(OAuthAccounts::RefreshToken))
                    .col(integer_null(OAuthAccounts::UserId))
                        .foreign_key(
                            ForeignKey::create()
                                .name("fk-oauth-user-id")
                                .from(OAuthAccounts::Table, OAuthAccounts::UserId)
                                .to(Users::Table, Users::Id)
                        )
                    .col(date_time(OAuthAccounts::CreatedAt))
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Replace the sample below with your own migration scripts

        manager
            .drop_table(Table::drop().table(OAuthAccounts::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum OAuthAccounts {
    Table,
    Id,
    Provider,
    ProviderAccountId,
    AccessToken,
    RefreshToken,
    UserId,
    CreatedAt
}

#[derive(DeriveIden)]
enum Users {
    Table,
    Id,
}