/*
authx mod support file - created by shivajiva101@hotmail.com

Use this file to import the data set from a Minetest 0.5 auth.sqlite
database file by copying it to the world folder you want to apply it
to and importing it with sqlite from that location.

See readme file for further information on using sqlite to import the
default db.
*/

PRAGMA foreign_keys=off;

ATTACH DATABASE "auth.sqlite" AS auth;

BEGIN TRANSACTION;

-- tables
CREATE TABLE IF NOT EXISTS active (
	id INTEGER(10) PRIMARY KEY,
	name VARCHAR(50),
	source VARCHAR(50),
	created INTEGER(30),
	reason VARCHAR(300),
	expires INTEGER(30),
	pos VARCHAR(50)
);

CREATE TABLE IF NOT EXISTS auth (
id INTEGER(10),
name VARCHAR(32) PRIMARY KEY,
password VARCHAR(512),
privileges VARCHAR(512),
last_login INTEGER(30),
login_count INTEGER(8) DEFAULT(1),
created INTEGER(30)
);
CREATE INDEX IF NOT EXISTS idx_auth_id ON auth(id);

CREATE TABLE IF NOT EXISTS expired (
	id INTEGER(10),
	name VARCHAR(50),
	source VARCHAR(50),
	created INTEGER(30),
	reason VARCHAR(300),
	expires INTEGER(30),
	u_source VARCHAR(50),
	u_reason VARCHAR(300),
	u_date INTEGER(30),
	last_pos VARCHAR(50)
);
CREATE INDEX IF NOT EXISTS idx_expired_id ON expired(id);

CREATE TABLE IF NOT EXISTS address (
	id INTEGER(10),
	ip VARCHAR(50) PRIMARY KEY,
	created INTEGER(30),
	last_login INTEGER(30),
	login_count INTEGER(8) DEFAULT(1),
	violation BOOLEAN
);
CREATE INDEX IF NOT EXISTS idx_address_id ON address(id);
CREATE INDEX IF NOT EXISTS idx_address_lastlogin ON address(last_login);

CREATE TABLE IF NOT EXISTS whitelist (
	name_or_ip VARCHAR(50) PRIMARY KEY,
	source VARCHAR(50),
	created INTEGER(30)
);

CREATE TABLE IF NOT EXISTS config (
	setting VARCHAR(28) PRIMARY KEY,
	data VARCHAR(255)
);

CREATE TABLE IF NOT EXISTS violation (
	id INTEGER PRIMARY KEY,
	data VARCHAR
);

-- itermediary table for priv conversion
CREATE TABLE IF NOT EXISTS auth_tmp (
id INTEGER(10),
name VARCHAR(32) PRIMARY KEY,
password VARCHAR(512),
privileges VARCHAR(512),
last_login INTEGER(30),
login_count INTEGER(8) DEFAULT(1),
created INTEGER(30)
);

-- copy data that doesn't req processing
INSERT INTO auth_tmp (id, name, password, last_login) SELECT id, name, password, last_login from auth.auth;

-- process privileges using group_concat
UPDATE auth_tmp
SET
    privileges = (
    SELECT group_concat(privilege) AS privileges FROM auth.user_privileges WHERE id = auth.id
);

-- copy data
INSERT OR REPLACE INTO auth (id, name, password, privileges, last_login) SELECT * from auth_tmp;

-- add import flag to config
INSERT INTO config (setting, data) VALUES ('auth', '1');

-- clean up
DROP TABLE auth_tmp;

COMMIT;

DETACH DATABASE auth;

PRAGMA foreign_keys=on;

VACUUM;
