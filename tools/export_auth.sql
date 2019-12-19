/*
authx mod support file - created by shivajiva101@hotmail.com

Use this file to import the data set to a Minetest 0.5 auth.sqlite
database file by copying it to the world folder you want to apply it
to and importing it with sqlite from that location.

See readme file for further information on using sqlite to import this
sql file.

*/

PRAGMA foreign_keys = OFF;

ATTACH DATABASE "auth.sqlite" as dest

BEGIN;

INSERT OR REPLACE INTO dest.auth
	SELECT id, name, password, last_login FROM auth;

INSERT OR REPLACE INTO dest.user_privileges
WITH RECURSIVE split(id, privilege, rest) AS (
  SELECT id, '', privileges || ',' FROM auth WHERE id
   UNION ALL
  SELECT id,
         substr(rest, 0, instr(rest, ',')),
         substr(rest, instr(rest, ',')+1)
    FROM split
   WHERE rest <> '')
SELECT id, privilege
  FROM split
 WHERE privilege <> ''
 ORDER BY id, privilege;

COMMIT;

DETACH DATABASE dest;

PRAGMA foreign_keys = ON;
