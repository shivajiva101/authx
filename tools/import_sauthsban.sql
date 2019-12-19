/*
authx mod support file - created by shivajiva101@hotmail.com

Use this file to import the data set from Minetest 0.5 sauth.sqlite
and sban.sqlite database files by copying them to the world folder you
want to apply it to and importing it with sqlite from that location.

See readme file for further information on using sqlite to import the
default db.
*/

PRAGMA foreign_keys = OFF;

ATTACH DATABASE 'sauth.sqlite' AS sauth;
ATTACH DATABASE 'sban.sqlite' AS sban;

BEGIN TRANSACTION;

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

INSERT OR REPLACE INTO auth
SELECT name.id, auth.name, password, privileges, auth.last_login, login_count, created
	FROM sauth.auth INNER JOIN sban.name ON sban.name.name = sauth.auth.name
	GROUP BY sauth.auth.name;

INSERT OR REPLACE INTO address
	SELECT * FROM sban.address WHERE address.ip NOT IN (SELECT ip FROM address);

INSERT OR REPLACE INTO active
	SELECT * FROM sban.active WHERE active.id NOT IN (SELECT id FROM active);

INSERT OR REPLACE INTO expired
	SELECT * FROM sban.expired;

INSERT OR REPLACE INTO violation
	SELECT * FROM sban.violation;

INSERT OR REPLACE INTO whitelist
	SELECT * FROM sban.whitelist;

-- add import flag to config
INSERT INTO config (setting, data) VALUES ('sauth', '1');
INSERT INTO config (setting, data) VALUES ('sban', '1');

COMMIT;

PRAGMA foreign_keys = ON;

VACUUM;
