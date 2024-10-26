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
