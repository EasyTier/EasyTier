// src/migrator/m20220602_000001_create_bakery_table.rs (create new file)


use sea_orm_migration::{prelude::*, schema::*};

pub struct Migration;

/*
-- # Entity schema.

-- Create `users` table.
create table if not exists users (
    id integer primary key autoincrement,
    username text not null unique,
    password text not null
);

-- Create `groups` table.
create table if not exists groups (
    id integer primary key autoincrement,
    name text not null unique
);

-- Create `permissions` table.
create table if not exists permissions (
    id integer primary key autoincrement,
    name text not null unique
);


-- # Join tables.

-- Create `users_groups` table for many-to-many relationships between users and groups.
create table if not exists users_groups (
    user_id integer references users(id),
    group_id integer references groups(id),
    primary key (user_id, group_id)
);

-- Create `groups_permissions` table for many-to-many relationships between groups and permissions.
create table if not exists groups_permissions (
    group_id integer references groups(id),
    permission_id integer references permissions(id),
    primary key (group_id, permission_id)
);


-- # Fixture hydration.

-- Insert "user" user. password: "user"
insert into users (username, password)
values (
    'user',
    '$argon2i$v=19$m=16,t=2,p=1$dHJ5dXZkYmZkYXM$UkrNqWz0BbSVBq4ykLSuJw'
);

-- Insert "admin" user. password: "admin"
insert into users (username, password)
values (
    'admin',
    '$argon2i$v=19$m=16,t=2,p=1$Ymd1Y2FlcnQ$x0q4oZinW9S1ZB9BcaHEpQ'
);

-- Insert "users" and "superusers" groups.
insert into groups (name) values ('users');
insert into groups (name) values ('superusers');

-- Insert individual permissions.
insert into permissions (name) values ('sessions');
insert into permissions (name) values ('devices');

-- Insert group permissions.
insert into groups_permissions (group_id, permission_id)
values (
    (select id from groups where name = 'users'),
    (select id from permissions where name = 'devices')
), (
    (select id from groups where name = 'superusers'),
    (select id from permissions where name = 'sessions')
);

-- Insert users into groups.
insert into users_groups (user_id, group_id)
values (
    (select id from users where username = 'user'),
    (select id from groups where name = 'users')
), (
    (select id from users where username = 'admin'),
    (select id from groups where name = 'users')
), (
    (select id from users where username = 'admin'),
    (select id from groups where name = 'superusers')
);
 */

impl MigrationName for Migration {
    fn name(&self) -> &str {
        "m20241029_000001_init"
    }
}

#[derive(DeriveIden)]
pub enum Users {
    Table,
    Id,
    Username,
    Password,
}

#[derive(DeriveIden)]
enum Groups {
    Table,
    Id,
    Name,
}

#[derive(DeriveIden)]
enum Permissions {
    Table,
    Id,
    Name,
}

#[derive(DeriveIden)]
enum UsersGroups {
    Table,
    Id,
    UserId,
    GroupId,
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
    // Define how to apply this migration: Create the Bakery table.
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Create the `users` table.
        manager
            .create_table(
                Table::create()
                    .if_not_exists()
                    .table(Users::Table)
                    .col(pk_auto(Users::Id).not_null())
                    .col(string(Users::Username).not_null().unique_key())
                    .col(string(Users::Password).not_null())
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_users_username")
                    .table(Users::Table)
                    .col(Users::Username)
                    .to_owned(),
            )
            .await?;

        // Create the `groups` table.
        manager
            .create_table(
                Table::create()
                    .if_not_exists()
                    .table(Groups::Table)
                    .col(pk_auto(Groups::Id).not_null())
                    .col(string(Groups::Name).not_null().unique_key())
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_groups_name")
                    .table(Groups::Table)
                    .col(Groups::Name)
                    .to_owned(),
            )
            .await?;

        // Create the `permissions` table.
        manager
            .create_table(
                Table::create()
                    .if_not_exists()
                    .table(Permissions::Table)
                    .col(pk_auto(Permissions::Id).not_null())
                    .col(string(Permissions::Name).not_null().unique_key())
                    .to_owned(),
            )
            .await?;

        // Create the `users_groups` table.
        manager
            .create_table(
                Table::create()
                    .if_not_exists()
                    .table(UsersGroups::Table)
                    .col(pk_auto(UsersGroups::Id).not_null())
                    .col(integer(UsersGroups::UserId).not_null())
                    .col(integer(UsersGroups::GroupId).not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_users_groups_user_id_to_users_id")
                            .from(UsersGroups::Table, UsersGroups::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_users_groups_group_id_to_groups_id")
                            .from(UsersGroups::Table, UsersGroups::GroupId)
                            .to(Groups::Table, Groups::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // Create the `groups_permissions` table.
        manager
            .create_table(
                Table::create()
                    .if_not_exists()
                    .table(GroupsPermissions::Table)
                    .col(pk_auto(GroupsPermissions::Id).not_null())
                    .col(integer(GroupsPermissions::GroupId).not_null())
                    .col(integer(GroupsPermissions::PermissionId).not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_groups_permissions_group_id_to_groups_id")
                            .from(GroupsPermissions::Table, GroupsPermissions::GroupId)
                            .to(Groups::Table, Groups::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_groups_permissions_permission_id_to_permissions_id")
                            .from(GroupsPermissions::Table, GroupsPermissions::PermissionId)
                            .to(Permissions::Table, Permissions::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // prepare data
        let user = Query::insert()
            .into_table(Users::Table)
            .columns(vec![Users::Username, Users::Password])
            .values_panic(vec![
                "user".into(),
                "$argon2i$v=19$m=16,t=2,p=1$dHJ5dXZkYmZkYXM$UkrNqWz0BbSVBq4ykLSuJw".into(),
            ])
            .to_owned();
        manager.exec_stmt(user).await?;

        let admin = Query::insert()
            .into_table(Users::Table)
            .columns(vec![Users::Username, Users::Password])
            .values_panic(vec![
                "admin".into(),
                "$argon2i$v=19$m=16,t=2,p=1$Ymd1Y2FlcnQ$x0q4oZinW9S1ZB9BcaHEpQ".into(),
            ])
            .to_owned();
        manager.exec_stmt(admin).await?;

        let users = Query::insert()
            .into_table(Groups::Table)
            .columns(vec![Groups::Name])
            .values_panic(vec!["users".into()])
            .to_owned();
        manager.exec_stmt(users).await?;

        let admins = Query::insert()
            .into_table(Groups::Table)
            .columns(vec![Groups::Name])
            .values_panic(vec!["admins".into()])
            .to_owned();
        manager.exec_stmt(admins).await?;

        let sessions = Query::insert()
            .into_table(Permissions::Table)
            .columns(vec![Permissions::Name])
            .values_panic(vec!["sessions".into()])
            .to_owned();
        manager.exec_stmt(sessions).await?;

        let devices = Query::insert()
            .into_table(Permissions::Table)
            .columns(vec![Permissions::Name])
            .values_panic(vec!["devices".into()])
            .to_owned();
        manager.exec_stmt(devices).await?;

        let users_devices = Query::insert()
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
                        // users have devices permission
                        Expr::col((Groups::Table, Groups::Name))
                            .eq("users")
                            .and(Expr::col((Permissions::Table, Permissions::Name)).eq("devices")),
                        // admins have all permissions
                        Expr::col((Groups::Table, Groups::Name)).eq("admins"),
                    ])
                    .to_owned(),
            )
            .unwrap()
            .to_owned();
        manager.exec_stmt(users_devices).await?;

        let add_user_to_users = Query::insert()
            .into_table(UsersGroups::Table)
            .columns(vec![UsersGroups::UserId, UsersGroups::GroupId])
            .select_from(
                Query::select()
                    .column((Users::Table, Users::Id))
                    .column((Groups::Table, Groups::Id))
                    .from(Users::Table)
                    .full_outer_join(Groups::Table, all![])
                    .cond_where(
                        Expr::col(Users::Username)
                            .eq("user")
                            .and(Expr::col(Groups::Name).eq("users")),
                    )
                    .to_owned(),
            )
            .unwrap()
            .to_owned();
        manager.exec_stmt(add_user_to_users).await?;

        let add_admin_to_admins = Query::insert()
            .into_table(UsersGroups::Table)
            .columns(vec![UsersGroups::UserId, UsersGroups::GroupId])
            .select_from(
                Query::select()
                    .column((Users::Table, Users::Id))
                    .column((Groups::Table, Groups::Id))
                    .from(Users::Table)
                    .full_outer_join(Groups::Table, all![])
                    .cond_where(
                        Expr::col(Users::Username)
                            .eq("admin")
                            .and(Expr::col(Groups::Name).eq("admins")),
                    )
                    .to_owned(),
            )
            .unwrap()
            .to_owned();
        manager.exec_stmt(add_admin_to_admins).await?;

        Ok(())
    }

    // Define how to rollback this migration: Drop the Bakery table.
    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Users::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Groups::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Permissions::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(UsersGroups::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(GroupsPermissions::Table).to_owned())
            .await?;
        Ok(())
    }
}
