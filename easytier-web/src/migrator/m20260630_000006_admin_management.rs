use sea_orm_migration::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20260630_000006_admin_management"
    }
}

#[derive(DeriveIden)]
enum Permissions {
    Table,
    Id,
    Name,
}

#[derive(DeriveIden)]
enum Groups {
    Table,
    Id,
    Name,
}

#[derive(DeriveIden)]
enum GroupsPermissions {
    Table,
    Id,
    GroupId,
    PermissionId,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Create the `manage_user` permission
        let manage_user_perm = Query::insert()
            .into_table(Permissions::Table)
            .columns(vec![Permissions::Name])
            .values_panic(vec!["manage_user".into()])
            .to_owned();
        manager.exec_stmt(manage_user_perm).await?;

        // Assign `manage_user` permission to `admins` group
        let assign = Query::insert()
            .into_table(GroupsPermissions::Table)
            .columns(vec![
                GroupsPermissions::GroupId,
                GroupsPermissions::PermissionId,
            ])
            .select_from(
                Query::select()
                    .column((Groups::Table, Groups::Id))
                    .column((Permissions::Table, Permissions::Id))
                    .from(Groups::Table)
                    .full_outer_join(Permissions::Table, all![])
                    .cond_where(any![
                        Expr::col((Groups::Table, Groups::Name))
                            .eq("admins")
                            .and(Expr::col((Permissions::Table, Permissions::Name)).eq("manage_user")),
                    ])
                    .to_owned(),
            )
            .unwrap()
            .to_owned();
        manager.exec_stmt(assign).await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Remove the `manage_user` permission from `admins` group
        // We need a delete with subquery for cleanup
        manager
            .exec_stmt(
                Query::delete()
                    .from_table(GroupsPermissions::Table)
                    .cond_where(
                        Expr::col((GroupsPermissions::Table, GroupsPermissions::PermissionId)).in_subquery(
                            Query::select()
                                .column(Permissions::Id)
                                .from(Permissions::Table)
                                .cond_where(Expr::col(Permissions::Name).eq("manage_user"))
                                .to_owned(),
                        ),
                    )
                    .to_owned(),
            )
            .await?;

        // Delete the `manage_user` permission itself
        manager
            .exec_stmt(
                Query::delete()
                    .from_table(Permissions::Table)
                    .cond_where(Expr::col(Permissions::Name).eq("manage_user"))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}