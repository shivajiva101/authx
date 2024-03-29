--[[
authx mod for Minetest designed and coded by shivajiva101@hotmail.com

request an insecure enviroment to load the db handler
and access files in the world folder. This requires
access via secure.trusted in the minetest.conf file
before it will work! For example:

secure.trusted = authx

]]

-- singleplayer behaviour
if minetest.is_singleplayer() then
	  minetest.log("info", "singleplayer game authx disabled")
	  return
end

local ie = minetest.request_insecure_environment()

-- Check insecure environment is available
if not ie then
	error("insecure environment inaccessible" ..
	" - make sure this mod has been added to the" ..
	" secure.trusted setting in minetest.conf!")
end

local _sql = ie.require("lsqlite3")

-- Secure this instance of sqlite3 global
if sqlite3 then sqlite3 = nil end

-- Register mod privileges
minetest.register_privilege("ban_admin", {
	description = "ban administrator",
	give_to_singleplayer = false,
	give_to_admin = true,
})

local WP = minetest.get_worldpath()
local MN = minetest.get_current_modname()
local MP = minetest.get_modpath(MN)
local MI = 100000 -- max auth records processed whilst loading
local WL -- whitelist cache
local BL -- blacklist cache
local ESC = minetest.formspec_escape
local FORMNAME = "authx:main"
local AUTHTXT = WP.."/auth.txt"
local DBF = WP.."/authx.sqlite"
local FILE3 = WP.."/auth.sql"
local FILE4 = WP.."/xban.sql"
local bans = {} -- ban cache
local auth_cache = {}
local ip_cache = {}
local hotlist = {}
local formstate = {}
local pjc = {}
local db_version = '0.0.1'
local db = _sql.open(DBF) -- connection
local mod_version = '0.2.0'
local expiry, owner, owner_id, def_duration, display_max, names_per_id
local importer, ID, HL_Max, max_cache_records, ttl, cap, ip_limit
local createDb, tmp_db, tmp_final
local t_units = {
	s = 1, S=1, m = 60, h = 3600, H = 3600,
	d = 86400, D = 86400, w = 604800, W = 604800,
	M = 2592000, y = 31104000, Y = 31104000, [""] = 1
}

cap = 0 -- initialise

-- Create global for API access
authx = {}

dofile(MP .. "/restrictions.lua")

--[[
################
### Settings ###
################
]]

-- Fetch settings from minetest.conf
if minetest.settings then
	expiry = minetest.settings:get("authx.ban_max")
	owner = minetest.settings:get("name")
	def_duration = minetest.settings:get("authx.fs_duration") or "1w"
	display_max = tonumber(minetest.settings:get("authx.display_max")) or 10
	names_per_id = tonumber(minetest.settings:get("authx.accounts_per_id"))
	ip_limit = tonumber(minetest.settings:get("authx.ip_limit"))
	importer = minetest.settings:get_bool("authx.import_enabled") or true
	HL_Max = tonumber(minetest.settings:get("authx.hotlist_max")) or 15
	max_cache_records = tonumber(minetest.settings:get("authx.cache.max")) or 1000
	ttl = tonumber(minetest.settings:get("authx.cache.ttl")) or 86400
else
	expiry = minetest.setting_get("authx.ban_max")
	owner = minetest.setting_get("name")
	def_duration = minetest.setting_get("authx.fs_duration") or "1w"
	display_max = tonumber(minetest.setting_get("authx.display_max")) or 10
	names_per_id = tonumber(minetest.setting_get("authx.accounts_per_id"))
	ip_limit = tonumber(minetest.setting_get("authx.ip_limit"))
	importer = minetest.setting_get_bool("authx.import_enabled") or true
	HL_Max = tonumber(minetest.setting_get("authx.hotlist_max")) or 15
	max_cache_records = tonumber(minetest.setting_get("authx.cache.max")) or 1000
	ttl = tonumber(minetest.setting_get("authx.cache.ttl")) or 86400
end

--[[
######################
###  DB callback  ###
######################
]]

-- Debugging ONLY!!!
-- Verbose logging of db operations
local debug = false
if debug then
	db:trace(
		function(ud, sql)
			minetest.log("action", "Sqlite Trace: " .. sql)
		end
	)

	-- Log the lines modified in the db
	optbl = {
		[_sql.UPDATE] = "UPDATE";
	    [_sql.INSERT] = "INSERT";
	    [_sql.DELETE] = "DELETE"
	 }
	setmetatable(optbl,
		{__index=function(t,n) return string.format("Unknown op %d",n) end})

	udtbl = {0, 0, 0}

	db:update_hook(
		function(ud, op, dname, tname, rowid)
			minetest.log("action", "[authx] " .. optbl[op] ..
			" applied to db table " .. tname .. " on rowid " .. rowid)
		end, udtbl
	)

end


--[[
##########################
###  Helper Functions  ###
##########################
]]

-- Execute sqlite statement on current db
---@param s string containing SQL statements
-- returns true or false with error message
local function db_exec(s)
	if db:exec(s) ~= _sql.OK then
		minetest.log("error", "Sqlite ERROR:  "..db:errmsg())
		return false, db:errmsg()
	else
		return true
	end
end

-- Check if param is an ip address
---@param str string
-- returns true if string contains ':' or '.'
local function is_ip(str)
	if str:find(":") or str:find("%.") then
		return true
	end
end

-- Escape special chars in a string
---@param str string
-- returns escaped string
local function escape_string(str)
	return str:gsub("'", "''")
end

-- Format ip string for keypair use
---@param str string
-- returns formatted string
local function ip_key(str)
	local r = str:gsub("%.", "")
	r:gsub('%:', '')
	return r
end


if importer then

	createDb = [[
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
	CREATE INDEX IF NOT EXISTS idx_auth_name ON auth(name);

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

	CREATE TABLE IF NOT EXISTS blacklist (
		name_or_ip VARCHAR(50) PRIMARY KEY,
		reason VARCHAR(300),
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

	]]
	db_exec(createDb)

	tmp_db = [[
	CREATE TABLE IF NOT EXISTS auth_tmp (
		id INTEGER(10),
		name VARCHAR(32),
		password VARCHAR(512),
		privileges VARCHAR(512),
		last_login INTEGER(30),
		login_count INTEGER(8) DEFAULT(1),
		created INTEGER(30)
	);

	CREATE TABLE IF NOT EXISTS address_tmp (
		id INTEGER(10),
		ip VARCHAR(50),
		created INTEGER(30),
		last_login INTEGER(30),
		login_count INTEGER(8) DEFAULT(1),
		violation BOOLEAN
	);

	CREATE TABLE IF NOT EXISTS active_tmp (
		id INTEGER(10),
		name VARCHAR(50),
		source VARCHAR(50),
		created INTEGER(30),
		reason VARCHAR(300),
		expires INTEGER(30),
		pos VARCHAR(50)
	);

	CREATE TABLE IF NOT EXISTS expired_tmp (
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

	]]

	tmp_final = [[

	-- remove duplicate data
	DELETE FROM auth_tmp WHERE rowid NOT IN (
		SELECT min(rowid) FROM auth_tmp GROUP BY name);

	DELETE FROM address_tmp WHERE rowid NOT IN (
		SELECT min(rowid) FROM address_tmp GROUP BY ip);

	DELETE FROM active_tmp where rowid NOT IN (
		SELECT min(rowid) FROM active_tmp GROUP BY id);

	-- insert distinct data
	INSERT INTO auth
		SELECT * FROM auth_tmp WHERE name NOT IN (SELECT name FROM auth);

	INSERT INTO address
		SELECT * FROM address_tmp WHERE ip NOT IN (SELECT ip FROM address);

	INSERT INTO active
		SELECT * FROM active_tmp WHERE id NOT IN (SELECT id FROM active);

	INSERT INTO expired
		SELECT * FROM expired_tmp;

	-- clean up
	DROP TABLE auth_tmp;
	DROP TABLE address_tmp;
	DROP TABLE active_tmp;
	DROP TABLE expired_tmp;

	COMMIT;

	PRAGMA foreign_keys = ON;

	VACUUM;
	]]
end

--[[
###########################
###  Database: Queries  ###
###########################
]]

--- Fetch id using players name
---@param name string
---@return integer or nil
local function get_id_by_name(name)
	local q = ([[
		SELECT id
		FROM auth
		WHERE name = '%s' LIMIT 1;]]
		):format(name)
		local it, state = db:nrows(q)
	local row = it(state)
	if row then
		return row.id
	end
end

--- Fetch id using players ip address
---@param ip_address string
---@return integer or nil
local function get_id_by_ip(ip_address)
	local q = ([[
		SELECT id
		FROM address
		WHERE ip = '%s' LIMIT 1;]]
	):format(ip_address)
	local it, state = db:nrows(q)
	local row = it(state)
	if row then
		return row.id
	end
end

-- Fetch last id from the name table
---@return integer id
local function last_id()
	local q = "SELECT MAX(id) AS id FROM auth;"
	local it, state = db:nrows(q)
	local row = it(state)
	if row then
		return row.id
	end
end

-- Fetch expired ban records for id
---@param id integer
-- returns ipair table of expired ban records
local function expired_bans(id)
	local r, q = {}
	q = ([[
	SELECT * FROM expired WHERE id = %i;
	]]):format(id)
	for row in db:nrows(q) do
		r[#r + 1] = row
	end
	return r
end

-- Fetch name records for id
---@param id integer
-- returns ipair table of name records ordered by last login
local function name_records(id)
	local r, q = {}
	q = ([[
		SELECT * FROM auth
		WHERE id = %i ORDER BY last_login DESC;
		]]):format(id)
	for row in db:nrows(q) do
		r[#r + 1] = row
	end
	return r
end

-- Fetch address records for id
---@param id integer
-- returns ipair table of ip address records ordered by last login
local function address_records(id)
	-- if not id then return end
	local r, q = {}
	q = ([[
		SELECT * FROM address
		WHERE id = %i ORDER BY last_login DESC;
		]]):format(id)
	for row in db:nrows(q) do
		r[#r + 1] = row
	end
	return r
end

-- Fetch violation records for id
---@param id integer
-- returns ipair table of violation records
local function violation_record(id)
	local q = ([[
		SELECT data FROM violation WHERE id = %i LIMIT 1;
	]]):format(id)
	local it, state = db:nrows(q)
	local row = it(state)
	if row then
		return minetest.deserialize(row.data)
	end
end

-- Fetch active bans
-- returns keypair table
local function get_active_bans()
	local r, q = {}
	q = "SELECT * FROM active;"
	for row in db:nrows(q) do
		r[row.id] = row
	end
	return r
end

-- Fetch whitelist
-- returns keypair table
local function get_whitelist()
	local r = {}
	local q = "SELECT * FROM whitelist;"
	for row in db:nrows(q) do
		r[row.name_or_ip] = true
	end
	return r
end

-- Fetch blacklist
-- returns keypair table
local function get_blacklist()
	local r = {}
	local q = "SELECT * FROM blacklist;"
	for row in db:nrows(q) do
		local key = row.name_or_ip
		if is_ip(key) then key = ip_key(key) end
		r[key] = row
	end
	return r
end

-- Fetch config setting
---@param setting_name string
-- returns data string
local function get_setting(setting_name)
	local q = ([[SELECT data FROM config WHERE setting = '%s';]]):format(setting_name)
	local it, state = db:nrows(q)
	local row = it(state)
	if row then
		return row.data
	end
end

-- Fetch names like 'name'
---@param name string
-- returns ipair table of names
local function get_names(name)
	local r,t,q = {},{}
	q = "SELECT name FROM auth WHERE name LIKE '%"..name.."%';"
	for row in db:nrows(q) do
		-- Simple sort using a temp table to remove duplicates
		if not t[row.name] then
			r[#r+1] = row.name
			t[row.name] = true
		end
	end
	return r
end

-- Fetch auth record by name
---@param name string
-- returns keypair record
local function auth_get_record(name)
	local q = ([[
	    SELECT * FROM auth WHERE name = '%s' LIMIT 1;
	]]):format(name)
	local it, state = db:nrows(q)
	local row = it(state)
	return row
end

-- Check auth records for match ignoring case
---@param name string
-- returns keypair table record
local function auth_check_name(name)
	local q = ([[
		SELECT DISTINCT name
		FROM auth
		WHERE LOWER(name) = LOWER('%s') LIMIT 1;
	]]):format(name)
	local it, state = db:nrows(q)
	local row = it(state)
	return row
end

-- Create table of auth names
---@return table keypair or {}
local function auth_get_names()
	local r,q = {}
	q = "SELECT name FROM auth;"
	for row in db:nrows(q) do
		r[row.name] = true
	end
	return r
end

--- Fetch utc timestamp of the last login
local function last_login_timestamp()
	local q = "SELECT max(last_login) AS login FROM auth;"
	local it, state = db:nrows(q)
	return it(state)
end

--- Fetch name list for players logging in after utc_int
---@param utc_int integer
-- returns ipair table of auth records
local function auth_cache_names(utc_int)
	local r = {}
	local q = ([[
		SELECT *
		FROM auth
		WHERE last_login > %i
		ORDER BY last_login ASC LIMIT %s;
		]]):format(utc_int, max_cache_records)
	for row in db:nrows(q) do
		r[#r+1] = row
	end
	return r
end


--[[
###########################
###  Database: Inserts  ###
###########################
]]

-- Create a new ip record
---@param id integer
---@param ip string
---@param timestamp integer
-- returns true or false with error message
local function add_ip_record(id, ip, timestamp)
	local s = ([[
		INSERT INTO address (
			id,
			ip,
			created,
			last_login,
			login_count,
			violation
		) VALUES (%i,'%s',%i,%i,1,0);
	]]):format(id, ip, timestamp, timestamp)
	return db_exec(s)
end

-- Create a new whitelist record
---@param source string
---@param name_or_ip string
---@param timestamp integer
-- returns true or false with error message
local function add_whitelist_record(source, name_or_ip, timestamp)
	local s = ([[
			INSERT INTO whitelist
				VALUES ('%s', '%s', %i)
	]]):format(name_or_ip, source, timestamp)
	return db_exec(s)
end

-- Create a new blacklist record
---@param source string
---@param name_or_ip string
---@param reason string
---@param timestamp integer
-- returns true or false with error message
local function add_blacklist_record(source, name_or_ip, reason, timestamp)
	local s = ([[
			INSERT INTO blacklist
			VALUES ('%s', '%s', '%s', %i)
	]]):format(name_or_ip, reason, source, timestamp)
	return db_exec(s)
end

-- Create a new ban record
---@param id integer
---@param name string
---@param source string
---@param reason string
---@param timestamp integer
---@param expires integer
---@param pos string
-- returns true or false with error message
local function create_ban_record(id, name, source, reason, timestamp, expires, pos)
	local s = ([[
		INSERT INTO active VALUES (%i,'%s','%s',%i,'%s',%i,'%s');
	]]):format(id, name, source, timestamp, reason, expires, pos)
	return db_exec(s)
end

-- Add a new setting to the config table
---@param setting string
---@param data string
-- returns true or false with error message
local function add_setting_record(setting, data)
	local s = ([[
		INSERT INTO config VALUES ('%s', '%s');
	]]):format(setting, data)
	return db_exec(s)
end

-- Create a new auth record
---@param id integer
---@param name string
---@param password string hash
---@param privs string
---@param last_login integer
-- returns true or false with error message
local function add_auth_record(id, name, password, privs, last_login)
	local s = ([[INSERT INTO auth (
		id,
		name,
		password,
		privileges,
		last_login,
		login_count,
		created
	) VALUES (%i,'%s','%s','%s',%i,%i,%i);
	]]):format(id, name, password, privs, last_login, 0, last_login)
	return db_exec(s)
end

-- Create a new violation record
---@param id integer
---@param data string
-- returns true or false with error message
local function add_idv_record(id, data)
	local s = ([[INSERT INTO violation VALUES (%i,'%s')]]
		):format(id, data)
	return db_exec(s)
end


--[[
###########################
###  Database: Updates  ###
###########################
]]

-- Update login for an auth record
---@param name string
---@param timestamp integer
-- returns true or false with error message
local function update_login_record(name, timestamp)
	local s = ([[
	UPDATE auth SET
	last_login = %i,
	login_count = login_count + 1
	WHERE name = '%s';
	]]):format(timestamp, name)
	return db_exec(s)
end

-- Update login for an address record
---@param id integer
---@param ip string
---@param timestamp integer
-- returns true or false with error message
local function update_address_record(id, ip, timestamp)
	local s = ([[
	UPDATE address
	SET
	last_login = %i,
	login_count = login_count + 1
	WHERE id = %i AND ip = '%s';
	]]):format(timestamp, id, ip)
	return db_exec(s)
end

-- Move ban to expired table & delete active record
---@param id integer
---@param source string
---@param reason string
---@param name string
---@param timestamp integer
-- returns true or false with error message
local function update_ban_record(id, source, reason, name, timestamp)
	local row = bans[id] -- use cached data
	local s = ([[
		INSERT INTO expired VALUES (%i,'%s','%s',%i,'%s',%i,'%s','%s',%i,'%s');
		DELETE FROM active WHERE id = %i;
	]]):format(row.id, row.name, row.source, row.created, escape_string(row.reason),
	row.expires, source, reason, timestamp, row.last_pos, row.id)
	return db_exec(s)
end

-- Update violation status for an ip
---@param ip string
-- returns true or false with error message
local function update_idv_status(ip)
	local s = ([[
	UPDATE address
	SET
	violation = vioation + 1
	WHERE ip = '%s';
	]]):format(ip)
	return db_exec(s)
end

-- Update auth record password field
---@param name string
---@param password string
-- returns true or false with error message
local function update_password(name, password)
	local s = ([[
		UPDATE auth SET password = '%s' WHERE name = '%s'
	]]):format(password, name)
	return db_exec(s)
end

-- Update auth record privileges field
---@param name string
---@param privs string
-- returns true or false with error message
local function update_privileges(name, privs)
	local s = ([[
		UPDATE auth SET privileges = '%s' WHERE name = '%s'
	]]):format(privs,name)
	return db_exec(s)
end

-- Update violation record data field
---@param id integer
---@param data string
-- returns true or false with error message
local function update_idv_record(id, data)
	local s = (
		[[UPDATE violation SET data = '%s' WHERE id = %i;]]
	):format(data, id)
	return db_exec(s)
end

--- Update config setting record
---@param setting any
---@param data any
-- returns true or false with error message
local function update_config_record(setting, data)
	local s = (
		[[UPDATE config SET data = '%s' WHERE setting = %s;]]
	):format(data, setting)
	return db_exec(s)
end


--[[
##################################
###  Database: Delete Records  ###
##################################
]]

-- Remove a ban record by id
---@param id integer
-- returns true or false with error message
local function del_ban_record(id)
	local s = ([[
		DELETE FROM active WHERE id = %i;
	]]):format(id)
	return db_exec(s)
end

-- Remove a whitelist record by name or ip
---@param name_or_ip string
-- returns true or false with error message
local function del_whitelist_record(name_or_ip)
	local s = ([[
		DELETE FROM whitelist WHERE name_or_ip = '%s';
	]]):format(name_or_ip)
	return db_exec(s)
end

-- Remove a blacklist entry by name or ip
---@param name_or_ip string
-- returns true or false with error message
local function del_blacklist_record(name_or_ip)
	local s = ([[
		DELETE FROM blacklist WHERE name_or_ip = '%s';
	]]):format(name_or_ip)
	return db_exec(s)
end

-- Remove an auth entry by name
---@param name string
-- returns true or false with error message
local function del_auth_record(name)
	local s = ([[
		DELETE FROM auth WHERE name = '%s';
	]]):format(name)
	return db_exec(s)
end

--- Remove address records by id
---@param id integer
-- returns true or false with error message
local function del_address_records(id)
	local s = ([[
		DELETE FROM address WHERE id = %i;
	]]):format(id)
	return db_exec(s)
end

--[[
###################
###  Functions  ###
###################
]]


-- Convert value to seconds (src: xban2)
---@param str string containing alphanumerical duration
-- returns integer seconds of duration
local function parse_time(str)
	local s = 0
	for n, u in str:gmatch("(%d+)([smhdwySHDWMY]?)") do
		s = s + (tonumber(n) * (t_units[u] or 1))
	end
	return s
end

-- Convert UTC integer to human readable date format
---@param utc_int integer, seconds since epoch
-- returns datetime string
local function hrdf(utc_int)
	if type(utc_int) == "number" then
		return (utc_int and os.date("%c", utc_int))
	end
end

-- Incrememnt db id
-- returns id
local function inc_id()
	ID = ID + 1
	return ID
end

-- Get an id by name or ip
---@param name_or_ip string
-- returns id integer
local function get_id(name_or_ip)
	local id
	if is_ip(name_or_ip) then
		-- Check cache first
		if ip_cache[ip_key(name_or_ip)] then
			return ip_cache[ip_key(name_or_ip)]
		end
		-- Check db
		id = get_id_by_ip(name_or_ip)

	else
		-- Check cache first
		if auth_cache[name_or_ip] then
			return auth_cache[name_or_ip].id
		end
		-- Check db
		id = get_id_by_name(name_or_ip)
	end
	return id
end

-- Kick players by name or id, a message is required
---@param name_or_id string or integer
---@param msg string
local function kick_player(name_or_id, msg)
	local r
	if type(name_or_id) == "number" then
		r = name_records(name_or_id)
	elseif type(name_or_id) == "string" then
		local id = get_id(name_or_id)
		if id then r = name_records(id) end
	end
	if r == {} then return end
	for i, v in ipairs(r) do
		local player = minetest.get_player_by_name(v.name)
		if player then
			-- defeat entity attached bypass mechanism
			-- minetest handles this from 5.1 onwards?
			player:set_detach()
			minetest.kick_player(v.name, msg)
		end
	end
end

-- Create and cache a new ban entry
---@param name string
---@param source string
---@param reason string
---@param expires integer
-- returns bool
local function create_ban(name, source, reason, expires)

	local ts = os.time()
	local id = get_id(name)
	local player = minetest.get_player_by_name(name)
	reason = escape_string(reason)

	expires = expires or 0

	-- initialise last position
	local last_pos = ""
	if player then
		last_pos = minetest.pos_to_string(vector.round(player:get_pos()))
	end

	local r = create_ban_record(id, name, source, reason, ts, expires, last_pos)
	if r then

		-- cache the ban
		bans[id] = {
			id = id,
			name = name,
			source = source,
			created = ts,
			reason = reason,
			expires = expires,
			last_pos = last_pos
		}

		-- create kick & log messages
		local kick_msg, log_msg
		if expires ~= 0 then
			local date = hrdf(expires)
			kick_msg = ("Banned: Expires: %s, Reason: %s"
			):format(date, reason)
			log_msg = ("[authx] %s temp banned by %s reason: %s"
			):format(name, source, reason)
		else
			kick_msg = ("Banned: Reason: %s"):format(reason)
			log_msg = ("[authx] %s banned by %s reason: %s"
			):format(name, source, reason)
		end
		minetest.log("action", log_msg)

		-- Ensure owner cannot be kicked
		-- debug: allow testing by developer
		if not debug and owner_id == id then return r end

		kick_player(id, kick_msg)
	else
		-- log failure
		minetest.log("warning", (
			[[[authx] Failed to create ban record for %s!]]
		):format(name))
	end
	return r
end

-- Create and caches a new ip record
---@param id integer
---@param ip string
-- returns bool
local function add_ip(id, ip)
	local ts = os.time()
	local r = add_ip_record(id, ip, ts)
	if r then
		ip_cache[ip_key(ip)] = id -- cache
	else
		minetest.log("warning", (
			[[[authx] Failed to add ip record for %i]]
		):format(id))
	end
	return r
end

-- Create a new auth record
---@param name string
---@param password string
---@param privs string
---@param last_login integer
-- returns bool
local function create_authx_entry(name, password, privs, last_login)
	local cache = pjc[name]
	local r = add_auth_record(cache.id, name, password, privs, last_login)
	if r then
		if cache.new then
			if not add_ip(cache.id, cache.ip) then
				minetest.log("warning", (
					[[[authx] Failed to add address record for %s]]
				):format(name))
				r = false
			end
		end
	else
		minetest.log("warning", (
			[[[authx] Failed to add auth record for %s]]
		):format(name))
	end
	return r
end

--- Add new config setting to db
---@param setting string
---@param data string
-- returns bool
local function add_setting(setting, data)
	local r = add_setting_record(setting, data)
	if not r then
		minetest.log("warning", (
			[[[authx] Failed to add %s setting to db!]]
		):format(setting))
	end
	return r
end

--- Create a new whitelist entry
---@param source string
---@param name_or_ip string
-- returns bool
local function add_whitelist_entry(source, name_or_ip)
	local ts = os.time()
	local r = add_whitelist_record(source, name_or_ip, ts)
	if not r then
		minetest.log("warning", (
			[[[authx] Failed to add whitelist record for %s]]
		):format(name_or_ip))
	end
	return r
end

-- Remove a whitelist entry
---@param name_or_ip string
-- returns bool
local function del_whitelist_entry(name_or_ip)
	local r = del_whitelist_record(name_or_ip)
	if not r then
		minetest.log("warning", (
			[[[authx] Failed to delete whitelist record for %s]]
		):format(name_or_ip))
	end
	return r
end

-- Create a new blacklist entry
---@param source string
---@param name_or_ip string
---@param reason string
-- returns bool
local function add_blacklist_entry(source, name_or_ip, reason)
	local ts = os.time()
	local r = add_blacklist_record(source, name_or_ip, reason, ts)
	if r then
		local key = name_or_ip
		if is_ip(key) then key = ip_key(key) end
		BL[key] = {
			name_or_ip = name_or_ip,
			reason = reason,
			source = source,
			created = ts
		}
	else
		minetest.log("warning", (
			[[[authx] Failed to add blacklist record for %s]]
		):format(name_or_ip))
	end
	return r
end

-- Remove a blacklist entry
---@param name_or_ip string
-- returns bool
local function del_blacklist_entry(name_or_ip)
	local r = del_blacklist_record(name_or_ip)
	if r then
		local key = name_or_ip
		if is_ip(key) then key = ip_key(key) end
		BL[key] = nil
	else
		minetest.log("warning", (
			[[[authx] Failed to delete blacklist record for %s]]
		):format(name_or_ip))
	end
	return r
end

-- Update an address entry
---@param id integer
---@param ip string
-- returns bool
local function update_address(id, ip)
	local ts = os.time()
	local r = update_address_record(id, ip, ts)
	if not r then
		minetest.log("warning", (
			[[[authx] Failed to update address for %s with id %i
			 in the address table]]
		):format(ip, id))
	end
	return r
end

-- Remove active ban entry
---@param id integer
---@param source string
---@param reason string
---@param name string
-- returns bool
local function update_ban(id, source, reason, name)
	reason = escape_string(reason)
	local ts = os.time()
	local r = update_ban_record(id, source, reason, name, ts)
	if r then
		bans[id] = nil -- update cache
		-- log event
		minetest.log("action", (
			"[authx] %s unbanned by %s reason: %s"
		):format(name, source, reason))
	end
	return r
end

-- Update auth entry login for a player
---@param name string
-- returns bool
local function update_login(name)
	local ts = os.time()
	local id = get_id(name)
	local r = update_login_record(name, ts)
	if r then
		auth_cache[name].last_login = ts
		auth_cache[name].login_count = auth_cache[name].login_count + 1
	else
		minetest.log("warning", (
			[[[authx] Failed to update login record
			for %s with id %i in the name table]]
		):format(name, id))
	end
	return r
end

--- Update db config setting
---@param setting any
---@param data any
-- returns bool
local function update_setting(setting, data)
	local r = update_config_record(setting, data)
	if not r then
		minetest.log("warning", (
			[[[authx] Failed to update db config setting %s]]
		):format(setting))
	end
	return r
end

-- Create new ip violation entry
---@param src_id integer
---@param target_id integer
---@param ip string
-- returns bool
local function manage_idv_record(src_id, target_id, ip)
	local ts = os.time()
	local record = violation_record(src_id)
	if record then
		local idx
		for i,v in ipairs(record) do
			if v.id == target_id and v.ip == ip then
				idx = i
				break
			end
		end
		if idx then
			-- update record
			record[idx].ctr = record[idx].ctr + 1
			record[idx].last_login = ts
		else
			-- add record
			record[#record+1] = {
				id = target_id,
				ip = ip,
				ctr = 1,
				created = ts,
				last_login = ts
			}
		end
		local r = update_idv_record(minetest.serialize(record), src_id)
		if not r then
			minetest.log("warning", (
			[[[authx] Failed to update violation record
			for id %i in the database]]
		):format(src_id))
		end
	else
		record = {
			id = target_id,
			ip = ip,
			ctr = 1,
			created = ts,
			last_login = ts
		}
		local r = add_idv_record(src_id, minetest.serialize(record))
		if not r then
			minetest.log("warning", (
			[[[authx] Failed to insert violation record
			for id %i in the database]]
		):format(src_id))
		end
	end
end

-- Get auth entry by name
---@param name string
-- returns keypair table record
local function auth_get(name)
	-- Prioritise cache
	if auth_cache[name] then return auth_cache[name] end
	return auth_get_record(name)
end

-- Remove ban records
---@param id integer
-- returns bool
local function del_ban(id)
	local r = del_ban_record(id)
	if r then
		bans[id] = nil -- update cache
	else
		minetest.log("warning", (
			[[[authx] Failed to delete ban record for id %i!]]
		):format(id))
	end
	return r
end

-- Build name and address cache
local function build_cache()

	local last = last_login_timestamp()

	if last and last.login then
		local result = auth_cache_names(last.login - ttl)
		if #result > 0 then
			for _, v in ipairs(result) do
				auth_cache[v.name] = {
					id = v.id,
					password = v.password,
					privileges = minetest.string_to_privs(v.privileges),
					last_login = v.last_login,
					login_count = v.login_count,
					created = v.created
				}
				cap = cap + 1
			end
		end

		minetest.log("action", "[authx] caching " .. cap .. " auth records")

		local ctr = 0
		for k, row in pairs(auth_cache) do
			for _,v in ipairs(address_records(row.id)) do
				if not ip_cache[ip_key(v.ip)] then
					ip_cache[ip_key(v.ip)] = row.id
					ctr = ctr + 1
				end
			end
		end

		minetest.log("action", "[authx] caching " .. ctr .. " ip records")

	end
end
build_cache()

-- Manages cache size by removing the earliest
-- entry by last_login when the cache is full
local function trim_cache()

	-- Check if cache size limit has been reached
	if cap < max_cache_records then return end

	-- Find the earliest last login in the cache
	local key, id
	local this = os.time()
	for k, v in pairs(auth_cache) do
		if v.last_login < this then
			-- Update
			this = v.last_login
			key = k
		end
	end

	-- Fetch id from the cache
	id = auth_cache[key].id

	-- Remove address cache entries by id
	for k,v in pairs(ip_cache) do
		if v == id then
			ip_cache[k] = nil
		end
	end

	-- Remove auth cache entry
	auth_cache[key] = nil
	cap = cap - 1 -- update cap value
end

-- Display player data in the console
---@param caller string
---@param target string
local function display_record(caller, target)

	local id = get_id(target)
	local r = name_records(id)
	local s = {}

	if not r then
		minetest.chat_send_player(caller, "No records for "..target)
		return
	end

	-- Show names
	local names = {}
	for i,v in ipairs(r) do
		table.insert(names, v.name)
	end
	s[#s+1] = minetest.colorize("#00FFFF", "[authx] records for: ") .. target
	s[#s+1] = minetest.colorize("#00FFFF", "Names: ") .. table.concat(names, ", ")

	local privs = minetest.get_player_privs(caller)

	-- Display records
	local idx = 1
	if #r > display_max then
		idx = #r - display_max
		s[#s+1] = minetest.colorize("#00FFFF", "Name records: ")..#r..
		minetest.colorize("#00FFFF", " (showing last ")..display_max..
		minetest.colorize("#00FFFF", " records)")
	else
		s[#s+1] = minetest.colorize("#00FFFF", "Name records: ")..#r
	end
	for i = idx, #r do
		local d1 = hrdf(r[i].created)
		local d2 = hrdf(r[i].last_login)
		s[#s+1] = (minetest.colorize("#FFC000",
		"[%s]").." Name: %s Created: %s Last login: %s"):format(i, r[i].name, d1, d2)
	end

	if privs.ban_admin == true then
		r = address_records(id)
		if #r > display_max then
			idx = #r - display_max
			s[#s+1] = minetest.colorize("#0FF", "IP records: ") .. #r ..
			minetest.colorize("#0FF", " (showing last ") .. display_max ..
			minetest.colorize("#0FF", " records)")
		else
			s[#s+1] = minetest.colorize("#0FF", "IP records: ") .. #r
			idx = 1
		end
		for i = idx, #r do
			-- Format utc values
			local d = hrdf(r[i].created)
			s[#s+1] = (minetest.colorize("#FFC000", "[%s] ")..
			"IP: %s Created: %s"):format(i, r[i].ip, d)
		end
		r = violation_record(id)
		if r then
			s[#s+1] = minetest.colorize("#0FF", "\nViolation records: ") .. #r
			for i,v in ipairs(r) do
				s[#s+1] = ("[%s] ID: %s IP: %s Created: %s Last login: %s"):format(
				i, v.id, v.ip, hrdf(v.created), hrdf(v.last_login))
			end
		else
			s[#s+1] = minetest.colorize("#0FF", "No violation records for ") .. target
		end
	end

	r = expired_bans(id) or {}
	s[#s+1] = minetest.colorize("#0FF", "Ban records:")
	if #r > 0 then

		s[#s+1] = minetest.colorize("#0FF", "Expired records: ")..#r

		for i, e in ipairs(r) do
			local d1 = hrdf(e.created)
			local expires = "never"
			if type(e.expires) == "number" and e.expires > 0 then
				expires = hrdf(e.expires)
			end
			local d2 = hrdf(e.u_date)
			s[#s+1] = (minetest.colorize("#FFC000", "[%s]")..
			" Name: %s Created: %s Banned by: %s Reason: %s Expires: %s "
		):format(i, e.name, d1, e.source, e.reason, expires) ..
			("Unbanned by: %s Reason: %s Time: %s"):format(e.u_source, e.u_reason, d2)
		end

	else
		s[#s+1] = "No expired ban records!"
	end

	r = bans[id]
	local ban = tostring(r ~= nil)
	s[#s+1] = minetest.colorize("#0FF", "Current Ban Status:")
	if ban == 'true' then
		local expires = "never"
		local d = hrdf(r.created)
		if type(r.expires) == "number" and r.expires > 0 then
			expires = hrdf(r.expires)
		end
		s[#s+1] = ("Name: %s Created: %s Banned by: %s Reason: %s Expires: %s"
		):format(r.name, d, r.source, r.reason, expires)
	else
		s[#s+1] = "no active ban record!"
	end
	s[#s+1] = minetest.colorize("#0FF", "Banned: ")..ban
	return table.concat(s, "\n")
end

--[[
########################
###  Authx Handlers  ###
########################
]]

authx.auth_handler = {

	-- fetch keypair record for player
	---@param name string player name
	---@param add_to_cache boolean defaults true
	-- returns keypair record or nil
	get_auth = function(name, add_to_cache)
		-- Check param
		assert(type(name) == 'string')
		add_to_cache = add_to_cache or true
		-- catch empty names - for mods doing privilege checks
		if name == nil or name == '' or name == ' ' then
			minetest.log("warning", "[authx] Name missing in call to get_auth. Rejected.")
			return nil
		elseif name:find("%'") then
			return nil
		end
		-- fetch record
		local r = auth_get(name)
		if not r then return nil end
		-- Figure out what privileges the player should have.
		-- Take a copy of the players privilege table
		local privileges
		if type(r.privileges) == "string" then
			-- db record, unpack it
			privileges = minetest.string_to_privs(r.privileges)
		else
			-- cached copy is unpacked
			privileges = r.privileges
		end
		-- Give owner all privs
		if name == owner then
			for priv, def in pairs(minetest.registered_privileges) do
				privileges[priv] = true
			end
		end
		-- Construct record
		local record = {
			id = r.id,
			password = r.password,
			privileges = privileges,
			last_login = r.last_login,
			login_count = r.login_count,
			created = r.created
			}
		-- Cache if reqd
		if add_to_cache and not auth_cache[name] then
			cap = cap + 1 -- increment the cap
			minetest.log('action', (
				[[[authx] caching record for %s]]
					):format(name))
		end
		if add_to_cache then auth_cache[name] = record end -- add or update
		return record
	end,

	--- create record
	---@param name string
	---@param password string
	-- returns true
	create_auth = function(name, password)
		-- Check params
		assert(type(name) == 'string')
		assert(type(password) == 'string')
		minetest.log('action',
			"[authx] authentication handler adding player '"..name.."'")
		-- Fetch default privs
		local privileges = minetest.settings:get("default_privs") or
			minetest.setting_get("default_privs")
		-- Strip spaces
		privileges = string.gsub(privileges, ' ', '')
		-- Create database records
		create_authx_entry(name, password, privileges, os.time())
		return true
	end,

	--- Delete auth record from database
	---@param name string
	---returns true
	delete_auth = function(name)
		-- Check param
		assert(type(name) == 'string')
		minetest.log('action',
			"[authx] authentication handler deleting player '"..name.."'")
		-- Check record exists
		if auth_get(name) then
			local id = get_id(name)
			del_auth_record(name)
			del_address_records(id)
			del_ban(id)
			auth_cache[name] = nil
			minetest.log("info",
				"[authx] Db records for " .. name .. " were deleted!")
			return true
		end
	end,

	--- Set password for auth record
	---@param name string
	---@param password string
	---returns true
	set_password = function(name, password)
		-- Check params
		assert(type(name) == 'string')
		assert(type(password) == 'string')
		-- Get player record
		if auth_get(name) == nil then
			authx.auth_handler.create_auth(name, password)
		else
			minetest.log('info',
				"[authx] authentication handler setting password of player '"..name.."'")
			-- Update record
			update_password(name, password)
			-- Update cache
			if auth_cache[name] then auth_cache[name].password = password end
		end
		return true
	end,

	--- Set privileges for a player
	---@param name string
	---@param privs table keypair
	set_privileges = function(name, privileges)
		-- Check params
		assert(type(name) == 'string')
		assert(type(privileges) == 'table')
		-- Fetch record
		local auth_entry = authx.auth_handler.get_auth(name)
		if not auth_entry then -- create new record
			local pw = minetest.settings:get("default_password") or
				minetest.setting_get("default_password")
			authx.auth_handler.create_auth(name,
				minetest.get_password_hash(name, pw))
			auth_entry = authx.auth_handler.get_auth(name)
		end
		-- Priv callback check
		if minetest.run_priv_callbacks then
			-- Run grant callbacks
			for priv, _ in pairs(privileges) do
				if not auth_entry.privileges[priv] then
					minetest.run_priv_callbacks(name, priv, nil, "grant")
				end
			end
			-- Run revoke callbacks
			for priv, _ in pairs(auth_entry.privileges) do
				if not privileges[priv] then
					minetest.run_priv_callbacks(name, priv, nil, "revoke")
				end
			end
		end
		-- Ensure owner has ability to grant
		if name == owner then privileges.privs = true end
		-- Update db
		update_privileges(name, minetest.privs_to_string(privileges))
		-- Update cache
		if auth_cache[name] then auth_cache[name].privileges = privileges end
		-- notify core this players auth changed
		minetest.notify_authentication_modified(name)
		return true
	end,

	--- Reload the database
	--- returns true
	reload = function()
		db:close_vm()
		db:close()
		db = _sql.open(DBF)
		return true
	end,

	--- Updates player last login
	---@param name string
	---returns true
	record_login = function(name)
		-- Check param
		assert(type(name) == 'string')
		update_login(name)
		return true
	end,

	--- Searches for names like name
	---@param name string
	---returns ipair table
	name_search = function(name)
		assert(type(name) == 'string')
		return get_names(name)
	end,

	--- Fetch all names in the auth table
	---returns iterator function
	iterate = function()
		return pairs(auth_get_names())
	end,
}

authx.ban_handler = {

	--- Bans known players
	---@param name string
	---@param source string
	---@param reason string
	---@param expires integer utc timestamp
	---returns boolean, message
	ban = function(name, source, reason, expires)
		-- Check params are valid
		assert(type(name) == 'string')
		assert(type(source) == 'string')
		assert(type(reason) == 'string')
		if expires and type(expires) == 'string' then
			expires = parse_time(expires)
		elseif expires and type(expires) == "integer" then
			local ts = os.time()
			if expires < ts then
				expires = ts + expires
			end
		end
		if name == owner then
			return false, 'insufficient privileges!'
		end
		local id = get_id(name)
		if not id then
			return false, ("No records exist for %s"):format(name)
		elseif bans[id] then
			-- Only one active ban per id is reqd!
			return false, ("An active ban already exist for %s"):format(name)
		end
		-- Ban player
		local r = create_ban(name, source, reason, expires)
		if r then return true, ("Banned %s."):format(name) end
	end,

	--- Unbans known players
	---@param name string
	---@param source string
	---@param reason string
	---returns boolean, message
	unban = function(name, source, reason)
		-- Check params are valid
		assert(type(name) == 'string')
		assert(type(source) == 'string')
		assert(type(reason) == 'string')
		-- Fetch records by id
		local id = get_id(name)
		if id then
			if not bans[id] then
				return false, ("No active ban record for "..name)
			end
			local r = update_ban(id, name, reason, name)
			if r then return true, ("Unbanned %s."):format(name) end
		else
			return false, ("No records exist for %s"):format(name)
		end
	end,

	--- Returns ban status of name or ip
	---@param name_or_ip string
	---returns boolean
	ban_status = function(name_or_ip)
		assert(type(name_or_ip) == 'string')
		local id = get_id(name_or_ip)
		return bans[id] ~= nil
	end,

	--- Returns ban record for name or ip
	---@param name_or_ip string
	---returns pair table
	ban_record = function(name_or_ip)
		assert(type(name_or_ip) == 'string')
		local id = get_id(name_or_ip)
		if id then
			return bans[id]
		end
	end,

	--- Returns table of bans
	---returns iterator(t)
	list_names = function()
		return pairs(bans)
	end
}



--[[
#######################
###  Export/Import  ###
#######################
]]

if importer then -- always true for first run

	--[[
	##########################
	###  Helper Functions  ###
	##########################
	]]

	-- Iterate pairs table for length
	---@param tbl table
	-- returns count integer
	local function tablelength(tbl)
		local i = 0
		for _ in pairs(tbl) do i = i + 1 end
		return i
	end

	-- Create SQL string
	---@param id integer
	---@param entry table
	-- returns formatted string
	local function sql_string(id, entry)
		local names = {}
		local ip = {}
		local last_seen = entry.last_seen or 0
		local last_pos = entry.last_pos or ""

		-- Names field includes both IP and names data, sort into 2 tables
		for k, v in pairs(entry.names) do
			if is_ip(k) then
				table.insert(ip, k)
			else
				table.insert(names, k)
			end
		end

		local q = {}

		for i, v in ipairs(names) do
			q[#q+1] = ([[INSERT INTO auth_tmp (
			id, name,) VALUES (%i,'%s',%i,%i, 0);]]
			):format(id, v, last_seen, last_seen)
		end
		for i, v in ipairs(ip) do
			-- address fields: id,ip,created,last_login,login_count,violation
			q = q..("INSERT INTO address_tmp VALUES (%i,'%s',%i,%i,1,0);\n"
			):format(id, v, last_seen, last_seen)
		end

		if #entry.record > 0 then

			local ts = os.time()
			-- Bans to archive
			for i, v in ipairs(entry.record) do

				local expires = v.expires or 0
				local reason = string.gsub(v.reason, "'", "''")

				reason = string.gsub(reason, "%:%)", "") -- remove colons

				if last_pos.y then
					last_pos = vector.round(last_pos)
					last_pos = minetest.pos_to_string(last_pos)
				end

				if entry.reason and entry.reason == v.reason then
					-- Active ban
					-- fields: id,name,source,created,reason,expires,last_pos
					q = q..("INSERT INTO active_tmp VALUES (%i,'%s','%s',%i,'%s',%i,'%s');\n"
					):format(id, names[1], v.source, v.time, reason, expires, last_pos)
				else
					-- Expired ban
					-- fields: id,name,source,created,reason,expires,u_source,u_reason,
					-- u_date,last_pos
					q = q..("INSERT INTO expired_tmp VALUES (%i,'%s','%s',%i,'%s',%i,'%s','%s',%i,'%s');\n"
					):format(id, names[1], v.source, v.time, reason, expires, 'authx',
					'expired prior to import', ts, last_pos)
				end
			end
		end

		return q
	end

	--[[
	#######################
	###  File Functions ###
	#######################
	]]

	-- Load and deserialise xban2 file
	---@param filename string
	-- returns table
	local function load_xban(filename)
		local f, e = ie.io.open(WP.."/"..filename, "rt")
		if not f then
			return false, "Unable to load xban2 database:" .. e
		end
		local content = f:read("*a")
		f:close()
		if not content then
			return false, "Unable to load xban2 database: Read failed!"
		end
		local t = minetest.deserialize(content)
		if not t then
			return false, "xban2 database: Deserialization failed!"
		end
		return t
	end

	-- Load ipban file
	-- returns string
	local function load_ipban()
		local f, e = ie.io.open(WP.."/ipban.txt")
		if not f then
			return false, "Unable to open 'ipban.txt': "..e
		end
		local content = f:read("*a")
		f:close()
		return content
	end

	-- Write sql file
	---@param filename string
	---@param txt string
	local function save_sql(filename, txt)
		local file = ie.io.open(WP.."/"..filename, "a")
		if file and txt then
			file:write(txt)
			file:close()
		end
	end

	-- Delete sql file
	-- returns nil
	local function del_sql(filename)
		ie.os.remove(filename)
	end

	--[[
	##########################
	###  Export Functions  ###
	##########################
	]]

	local function export_auth()
		local file, errmsg = ie.io.open(AUTHTXT, 'rb')
		if not file then
			minetest.log("info", AUTHTXT..
			" could not be opened for reading ("..errmsg..")")
			return
		end
		del_sql(FILE3)
		-- Create export file by appending lines
		local sb = {}
		local id
		local ts = os.time()
		sb[#sb+1] = createDb
		sb[#sb+1] = "BEGIN;\n"
		for line in file:lines() do
			if line ~= "" then
				local fields = line:split(":", true)
				local name, password, privs, last_login = unpack(fields) -- luacheck: ignore
				last_login = tonumber(last_login)
				if (name and password and privs) then
					id = inc_id()
					sb[#sb+1] = ([[INSERT OR REPLACE INTO auth VALUES (
					%i, '%s','%s','%s', %i, 1, %i);]]):format(id, name, password,
					privs, last_login, ts)
					save_sql(FILE3, table.concat(sb, "\n"))
					sb = {}
				end
			end
		end
		sb[#sb+1] = "COMMIT;\n"
		ie.io.close(file) -- close auth.txt
		save_sql(FILE3, table.concat(sb, "\n")) -- finalise
		ie.os.remove(DBF) -- remove existing db
		minetest.request_shutdown("Server Shutdown requested...", false, 5)
	end

	-- Export xban2 file to SQL file
	---@param filename string
	local function export_sql(filename)
		-- load the db, iterate in reverse order and remove each
		-- record to balance the memory use otherwise large files
		-- cause lua OOM error
		local dbi, err = load_xban(filename)
		local id = ID
		if err then
			minetest.log("info", err)
			return
		end
		-- reverse the contents
		for i = 1, math.floor(#dbi / 2) do
			local tmp = dbi[i]
			dbi[i] = dbi[#dbi - i + 1]
			dbi[#dbi - i + 1] = tmp
		end

		save_sql(FILE4, "PRAGMA foreign_keys = OFF;\n\n")
		save_sql(FILE4, createDb)
		save_sql(FILE4, tmp_db)
		save_sql(FILE4, "BEGIN TRANSACTION;\n\n")
		-- process records
		for i = #dbi, 1, - 1 do
			-- contains data?
			if dbi[i] then
				id = id + 1
				local str = sql_string(id, dbi[i]) -- sql statement
				save_sql(FILE4, str)
				dbi[i] = nil -- shrink
			end
		end
		-- add sql inserts to transfer the data, clean up and finalise
		save_sql(FILE4, tmp_final)
	end

	-- Export db bans to xban2 file format
	-- returns nil
	local function export_to_xban()
		local xport = {}
		local DEF_DB_FILENAME = WP.."/xban.db"
		local DB_FILENAME = minetest.setting_get("xban.db_filename")

		if (not DB_FILENAME) or (DB_FILENAME == "") then
			DB_FILENAME = DEF_DB_FILENAME
		end

		-- initialise table of banned id's
		for k,v in pairs(bans) do
			local id = v.id
			xport[id] = {
				banned = true,
				names = {}
			}
			local t = {}
			local q = ([[SELECT * FROM name
			WHERE id = %i]]):format(id)
			for row in db:nrows(q) do
				xport[id].names[row.name] = true
			end
			q = ([[SELECT * FROM address
			WHERE id = %i]]):format(id)
			for row in db:nrows(q) do
				xport[id].names[row.ip] = true
			end
			q = ([[SELECT * FROM expired WHERE id = %i;]]):format(id)
			for row in db:nrows(q) do
				t[#t+1] = {
					time = row.created,
					source = row.source,
					reason = row.reason
				}
			end
			t[#t+1] = {
				time = bans[id].created,
				source = bans[id].source,
				reason = bans[id].reason
			}
			xport[id].record = t
			xport[id].last_seen = bans[id].last_login
			xport[id].last_pos = bans[id].last_pos or ""
		end

		local function repr(x)
			if type(x) == "string" then
				return ("%q"):format(x)
			else
				return tostring(x)
			end
		end

		local function my_serialize_2(t, level)
			level = level or 0
			local lines = { }
			local indent = ("\t"):rep(level)
			for k, v in pairs(t) do
				local typ = type(v)
				if typ == "table" then
					table.insert(lines,
					  indent..("[%s] = {\n"):format(repr(k))
					  ..my_serialize_2(v, level + 1).."\n"
					  ..indent.."},")
				else
					table.insert(lines,
					  indent..("[%s] = %s,"):format(repr(k), repr(v)))
				end
			end
			return table.concat(lines, "\n")
		end

		local function this_serialize(t)
			return "return {\n"..my_serialize_2(t, 1).."\n}"
		end

		local f, e = io.open(DB_FILENAME, "wt")
		xport.timestamp = os.time()
		if f then
			local ok, err = f:write(this_serialize(xport))
			if not ok then
				minetest.log("error", "Unable to save database: %s", err)
			end
		else
			minetest.log("error", "Unable to save database: %s", e)
		end
		if f then f:close() end
	end

	--[[
	##########################
	###  Import Functions  ###
	##########################
	]]

	local function read_auth_file()
		local result = {}
		local ts = os.time()
		local file, errmsg = ie.io.open(AUTHTXT, 'rb')
		if not file then
			minetest.log("info", AUTHTXT .. " missing! ("..errmsg..")")
			return false, errmsg
		end
		for line in file:lines() do
			if line ~= "" then
				local fields = line:split(":", true)
				local name, password, privilege_string, last_login = unpack(fields) -- luacheck: ignore
				last_login = tonumber(last_login)
				if (name and password and privilege_string) and not result[name] then
					result[name] = {
						password = password,
						privileges = privilege_string,
						last_login = last_login,
						login_count = 1,
						created = ts
					}
				else
					minetest.log("info", "Invalid record in auth.txt: " .. line)
				end
			end
		end
		ie.io.close(file)
		return result
	end

	-- Import xban2 file active ban records
	---@param file_name string
	local function import_xban(file_name)

		local t, err = load_xban(file_name)

		if not t then -- exit with error message
			return false, err
		end

		local id = ID
		local bl = {}
		local tl = {}

		minetest.log("action", "processing "..#t.." records")

		for i, v in ipairs(t) do
			if v.banned == true then
				bl[#bl+1] = v
				t[i] = nil
			end
		end

		minetest.log("action", "found "..#bl.." active ban records")

		tl[#tl+1] = "PRAGMA foreign_keys = OFF;\n"
		tl[#tl+1] = tmp_db
		tl[#tl+1] = "BEGIN TRANSACTION;"

		for i = #bl, 1, -1 do
			if bl[i] then
				id = id + 1
				tl[#tl+1] = sql_string(id, bl[i])
				bl[i] = nil -- shrink
			end
		end

		tl[#tl+1] = tmp_final
		-- Run the prepared statement
		db_exec(table.concat(tl, "\n"))
		ID = id -- update global
		return true
	end

	-- Import ipban file records
	local function import_ipban()
		local contents = load_ipban()
		if not contents then
			return false
		end
		local data = string.split(contents, "\n")
		for i, v in ipairs(data) do
			-- Each line consists of an ip, separator and name
			local ip, name = v:match("([^|]+)%|(.+)")
			if ip and name then
				-- Check for an existing entry by name
				local id = get_id(name)
				if not id then
					-- Create blacklist entries
					add_blacklist_entry('authx', name,
						'existing ban imported from ipban')
					add_blacklist_entry('authx', ip,
						'existing ban imported from ipban')
				else
					-- Check for existing ban
					if not bans[id] then
						-- Create ban entry - name,source,reason,expires
						create_ban(name, 'authx', 'imported from ipban.txt', 0)
					end
				end
			end
		end
	end

	local function db_import()

		local sb = {}
		local id
		local auth = read_auth_file()

		sb[#sb+1] = 'BEGIN;\n'
		for name, stuff in pairs(auth) do
			id = inc_id()
			sb[#sb+1] = ([[INSERT OR REPLACE INTO auth
			VALUES (%i,'%s','%s','%s',%i,%i,%i)]]):format(id, name, stuff.password,
			stuff.privileges, stuff.last_login, stuff.login_count, stuff.created)
		end
		sb[#sb+1] = '\nCOMMIT;'

		-- execute
		local result, err = db_exec(table.concat(sb, "\n"))
		-- check
		if result then
			if not get_setting("auth_import") then
				add_setting("auth_import", 'true') -- set db flag
			end
		end

		return result, err
	end

	local function import_auth_legacy()
		-- load auth.txt
		local tbl = read_auth_file()
		local len = tablelength(tbl)
		if len < 1 then
			minetest.log("info", "[authx] nothing to import!")
			return
		end
		-- limit size
		if len < MI then db_import() end
		-- are we there yet?
		if get_setting("import") == nil then export_auth() end -- dump to sql
		-- rename auth.txt
		ie.os.rename(WP.."/auth.txt", WP.."/auth.txt.safe")
		-- finally
		minetest.notify_authentication_modified()
		return 0
	end

	--[[
	###########################
	###  Register Commands  ###
	###########################
	]]

	-- Register export to SQL file command
	minetest.register_chatcommand("ban_dbe", {
		description = "export xban2 db to sql format",
		params = "<filename>",
		privs = {server = true},
		func = function(name, params)
			local filename = params:match("%S+")
			if not filename then
				return false, "Use: /ban_dbe <filename>"
			end
			del_sql()
			export_sql(filename)
			return true, filename .. " dumped to xban.sql"
		end
	})

	-- Register export to xban2 file format
	minetest.register_chatcommand("ban_dbx", {
		description = "export db to xban2 format",
		privs = {server = true},
		func = function(name)
			export_to_xban()
			return true, "dumped db to xban2 file!"
		end
	})

	-- Register ban import command
	minetest.register_chatcommand("ban_dbi", {
		description = "Import bans",
		params = "<filename>",
		privs = {server = true},
		func = function(name, params)
			local filename = params:match("%S+")
			if not filename then
				return false, "Use: /ban_dbi <filename>"
			end
			local msg
			if filename == "ipban.txt" then
				import_ipban()
				msg = "ipban.txt imported!"
			else
				local res, err = import_xban(filename)
				msg = err
				if res then
					msg = filename.." bans imported!"
				end
			end
			return true, msg
		end
	})

	local auth_import = get_setting("auth_import")
	if auth_import then
		-- check for auth.txt
		if import_auth_legacy() == 0 then
			return
		end
		-- check for auth.sqlite
		-- finally set auth_import to true
	end
end

--[[
##############
###  Misc  ###
##############
]]

-- Initialise current config
local current_db_version = get_setting("db_version")
local current_mod_version = get_setting("mod_version")

if not current_db_version then -- first run
	add_setting('db_version', db_version)
	add_setting('mod_version', mod_version)
elseif not current_db_version == db_version then
	error("You must update authx database to "..db_version..
	"\nUse sqlite3 to import /tools/authban_update.sql")
end

-- Check & update mod version in db
if not current_mod_version == mod_version then
	update_setting("mod_version", mod_version)
end

-- initialise caches
WL = get_whitelist()
BL = get_blacklist()
bans = get_active_bans()
ID = last_id() or 0
owner_id = get_id(owner)

-- Add name to hotlist
---@param name string
local function add_hotlist_entry(name)
	for _, v in ipairs(hotlist) do
		if v == name then
			return -- no duplicates
		end
	end
	-- fifo
	table.insert(hotlist, name)
	if #hotlist > HL_Max then
		table.remove(hotlist, 1)
	end
end

-- Manage expired bans on mod load
local function process_expired_bans()
	local ts = os.time()
	local tq = {}
	for id_key,row in pairs(bans) do
		if type(row.expires) == "number" and row.expires ~= 0 then
			-- temp ban
			if ts > row.expires then
				row.last_pos = row.last_pos or "" -- can't be nil!
				-- add sql statements
				tq[#tq+1] = ([[
					INSERT INTO expired VALUES (%i,'%s','%s',%i,'%s',%i,'authx','tempban expired',%i,'%s');
					DELETE FROM active WHERE id = %i;
				]]):format(row.id, row.name, row.source, row.created, escape_string(row.reason),
				row.expires, ts, row.last_pos, row.id)
			end
		end
	end
	if #tq > 0 then
		-- finalise & execute
		tq[#tq+1] = "VACUUM;"
		db_exec(table.concat(tq, "\n"))
	end
end
process_expired_bans() -- trigger on mod load

-- Modify irc mod with an override
if minetest.get_modpath('irc') ~= nil then
    irc.reply = function(message) -- luacheck: ignore
        if not irc.last_from then -- luacheck: ignore
            return
        end
        message = message:gsub("[\r\n%z]", " \\n ")
        local helper = string.split(message, "\\n")
        for i,v in ipairs(helper) do
            irc.say(irc.last_from, minetest.strip_colors(v)) -- luacheck: ignore
        end
    end
end

--[[
#######################
###  GUI Functions  ###
###  & Callback     ###
#######################
]]

-- Fetch and format ban info
---@param entry table
-- returns formatted string
local function create_info(entry)
	-- returns an info string, line wrapped based on the ban record
	if not entry then
		return "something went wrong!\n Please reselect the entry."
	end
	local str = "Banned by: "..entry.source.."\n"
		.."When: "..hrdf(entry.created).."\n"
	if entry.expires ~= 0 then
		str = str.."Expires: "..hrdf(entry.expires).."\n"
	end
	str = str .."Reason: "
	-- Word wrap
	local words = entry.reason:split(" ")
	local l,ctr = 40,8 -- initialise limits
	for _,word in ipairs(words) do
		local wl = word:len()
		if ctr + wl < l then
			str = str..word.." "
			ctr = ctr + (wl + 1)
		else
			str = str.."\n"..word.." "
			ctr = wl + 1
		end
	end
	return str
end

-- Get formstate, initialising if reqd
---@param name string
-- returns keypair state table
local function get_state(name)
	local s = formstate[name]
	if not s then
		s = {
			list = {},
			hlist = {},
			index = -1,
			info = "Select an entry from the list\n or use search",
			banned = false,
			ban = nil,
			multi = false,
			page = 1,
			flag = false
		}
		formstate[name] = s
	end
	return s
end

-- Update state table
---@param name string
---@param selected string
-- returns nil
local function update_state(name, selected)
	-- updates state used by formspec
	local fs = get_state(name)
	local id = get_id(selected)

	fs.ban = expired_bans(id)
	local cur = bans[id]
	if cur then table.insert(fs.ban, cur) end

	local info = "Ban records: "..#fs.ban.."\n"

	fs.banned = cur
	fs.multi = false

	if #fs.ban == 0 then
		info = info.."Player has no ban records!"
	else
		if not fs.flag then
			fs.page = #fs.ban
			fs.flag = true
		end
		if fs.page > #fs.ban then fs.page = #fs.ban end
		info = info..create_info(fs.ban[fs.page])
	end

	fs.info = info
	if #fs.ban > 1 then
		fs.multi = true
	end
end

-- Fetch user formspec
---@param name string
-- returns formspec string
local function getformspec(name)

	local fs = formstate[name]
	local f
	local list = fs.list
	local bgimg = ""
	if default and default.gui_bg_img then
		bgimg = default.gui_bg_img
	end

	f = {}
	f[#f+1] = "size[8,6.6]"
	f[#f+1] = bgimg
	f[#f+1] = "field[0.3,0.4;4.5,0.5;search;;]"
	f[#f+1] = "field_close_on_enter[search;false]"
	f[#f+1] = "button[4.5,0.1;1.5,0.5;find;Find]"
	if #fs.list > 0 then
		f[#f+1] = "textlist[0,0.9;2.4,3.6;plist;"
		local tmp = {}
		for i,v in ipairs(list) do
			tmp[#tmp+1] = v
		end
		f[#f+1] = table.concat(tmp, ",")
		f[#f+1] = ";"
		f[#f+1] = fs.index
		f[#f+1] = "]"
	end
	f[#f+1] = "field[0.3,6.5;4.5,0.5;reason;Reason:;]"
	f[#f+1] = "field_close_on_enter[reason;false]"

	if fs.multi == true then
		f[#f+1] = "image_button[6,0.1;0.5,0.5;ui_left_icon.png;left;]"
		f[#f+1] = "image_button[7,0.1;0.5,0.5;ui_right_icon.png;right;]"
		if fs.page > 9 then
			f[#f+1] = "label[6.50,0.09;"
			f[#f+1] = fs.page
			f[#f+1] = "]"
		else
			f[#f+1] = "label[6.55,0.09;"
			f[#f+1] = fs.page
			f[#f+1] = "]"
		end
	end

	f[#f+1] = "label[2.6,0.9;"
	f[#f+1] = fs.info
	f[#f+1] = "]"

	if fs.banned then
		f[#f+1] = "button[4.5,6.2;1.5,0.5;unban;Unban]"
	else
		f[#f+1] = "field[0.3,5.5;2.6,0.3;duration;Duration:;"
		f[#f+1] = def_duration
		f[#f+1] = "]"
		f[#f+1] = "field_close_on_enter[duration;false]"
		f[#f+1] = "button[4.5,6.2;1.5,0.5;ban;Ban]"
		f[#f+1] = "button[6,6.2;2,0.5;tban;Temp Ban]"
	end

	return table.concat(f)
end

-- Register callback for form submission
minetest.register_on_player_receive_fields(function(player, formname, fields)

	-- Only handle this form!
	if formname ~= FORMNAME then return end

	local name = player:get_player_name()
	local privs = minetest.get_player_privs(name)

	if not privs.ban then
		minetest.log(
		"warning", "[authx] Received fields from unauthorized user: "..name)
		create_ban(name, 'authx',
		'detected using a hacked client to access the ban GUI!', 0)
		return
	end

	local fs = get_state(name)

	if fields.find then

		if fields.search:len() > 2 then
			fs.list = get_names(ESC(fields.search))
		else
			fs.list = fs.hlist
		end
		local str = "No record found!"
		if #fs.list > 0 then
			str = "Select an entry to see the details..."
		end
		fs.info = str
		fs.index = -1
		fs.multi = false
		minetest.show_formspec(name, FORMNAME, getformspec(name))

	elseif fields.plist then

		local t = minetest.explode_textlist_event(fields.plist)

		if (t.type == "CHG") or (t.type == "DCL") then

			fs.index = t.index
			fs.flag = false -- reset
			update_state(name, fs.list[t.index])
			minetest.show_formspec(name, FORMNAME, getformspec(name))
		end

	elseif fields.left or fields.right then

		if fields.left then
			if fs.page > 1 then fs.page = fs.page - 1 end
		else
			if fs.page < #fs.ban then fs.page = fs.page + 1 end
		end
		update_state(name, fs.list[fs.index])
		minetest.show_formspec(name, FORMNAME, getformspec(name))

	elseif fields.ban or fields.unban or fields.tban then

		local selected = fs.list[fs.index]
		local id = get_id(selected)

		if fields.reason ~= "" then
			if fields.ban then
				if selected == owner then
					fs.info = "you do not have permission to do that!"
				else
					create_ban(selected, name, ESC(fields.reason), 0)
				end
			elseif fields.unban then
				update_ban(id, name, ESC(fields.reason), selected)
				fs.ban = expired_bans(id)
			elseif fields.tban then
				if selected == owner then
					fs.info = "you do not have permission to do that!"
				else
					local  t = parse_time(ESC(fields.duration)) + os.time()
					create_ban(selected, name, ESC(fields.reason), t)
				end
			end
			fs.flag = false -- reset
			update_state(name, selected)
		else
			fs.info = "You must supply a reason!"
		end
		minetest.show_formspec(name, FORMNAME, getformspec(name))
	end
end)

--[[
###################################
###  Register Console Commands  ###
###################################
]]

-- Override default ban command
minetest.override_chatcommand("ban", {
	description = "Ban player accessing the server",
	params = "<player> <reason>",
	privs = { ban = true },
	func = function(name, params)
		local player_name, reason = params:match("(%S+)%s+(.+)")

		if not (player_name and reason) then
			-- check params are present
			return false, "Usage: /ban <player> <reason>"
		end

		if player_name == owner then
			-- protect owner
			return false, "Insufficient privileges!"
		end

		local expires = 0
		local id = get_id(player_name)
		local r

		if id then
			-- check for existing ban
		   if bans[id] then
			   return true, ("%s is already banned!"):format(player_name)
		   end
			-- limit ban?
			if expiry then
				expires = parse_time(expiry) + os.time()
			end
			-- Params: name, source, reason, expires
			r = create_ban(player_name, name, reason, expires)
		else
			local privs = minetest.get_player_privs(name)
			-- ban_admin only
			if not privs.ban_admin then
				return false, "Player "..player_name.." doesn't exist!"
			end
			-- create blacklist entry
			r = add_blacklist_entry(name, player_name, reason)
		end
		if r then return true, ("Banned %s."):format(player_name) end
	end
})

-- Register GUI command
minetest.register_chatcommand("bang", {
	description = "Launch authx gui",
	privs = {ban = true},
	func = function(name)
		formstate[name] = nil
		local fs = get_state(name)
		fs.list = hotlist
		for i,v in ipairs(fs.list) do
			fs.hlist[i] = v
		end
		minetest.show_formspec(name, FORMNAME, getformspec(name))
	end
})

-- Register ban deletion command
minetest.register_chatcommand("ban_del", {
	description = "Deletes a player's authx records",
	params = "player",
	privs = {server = true},
	func = function(name, params)
		local player_name = params:match("%S+")
		if not player_name then
			return false, "Usage: /ban_del_record <player>"
		end
		local id = get_id(player_name)
		if not id then
			return false, player_name.." doesn't exist!"
		end
		local r = del_ban(id)
		if r then
			minetest.log("action", (
				"ban records for %s deleted by %s"
			):format(player_name, name))
			return true, player_name.." ban records deleted!"
		end
	end
})

-- Register info command
minetest.register_chatcommand("ban_record", {
	description = "Display player authx records",
	params = "<player_or_ip>",
	privs = { ban = true },
	func = function(name, params)
		local playername = params:match("%S+")
		if not playername or playername:find("*") then
			return false, "usage: /ban_record <player_name>"
		end
		-- get target and source privs
		local id = get_id(playername)
		if not id then
			return false, "Unknown player!"
		end
		local target = name_records(id)
		local source = minetest.get_player_privs(name)
		local chk = false
		for i, v in ipairs(target) do
			local privs = minetest.get_player_privs(v.name)
			if privs.server then chk = true break end
		end
		-- if source doesn't have sufficient privs deny & inform
		if not source.server and chk then
			return false, "Insufficient privileges to access that information"
		end
		return true, display_record(name, playername)
	end
})

-- Override default kick command
minetest.override_chatcommand("kick", {
	params = "<name> [reason]",
	description = "Kick a player",
	privs = {kick=true},
	func = function(name, param)
		local tokick, reason = param:match("([^ ]+) (.+)")
		tokick = tokick or param
		local player = minetest.get_player_by_name(tokick)
		if not player then
			return false, "Player " .. tokick .. " not in game!"
		end
		if not minetest.kick_player(tokick, reason) then
			player:set_detach() -- reqd for > 5.0 ?
			if not minetest.kick_player(tokick, reason) then
				return false, "Failed to kick player " .. tokick ..
				" after detaching!"
			end
		end
		local log_reason = ""
		if reason then
			log_reason = " with reason \"" .. reason .. "\""
		end
		minetest.log("action", name .. " kicks " .. tokick .. log_reason)
		return true, "Kicked " .. tokick
  end,
})

-- Register temp ban command
minetest.register_chatcommand("tempban", {
	description = "Ban a player temporarily with authx",
	params = "<player> <time> <reason>",
	privs = { ban = true },
	func = function(name, params)
		local player_name, time, reason = params:match("(%S+)%s+(%S+)%s+(.+)")

		if not (player_name and time and reason) then
			-- correct params?
			return false, "Usage: /tempban <player> <time> <reason>"
		end

		if player_name == owner then
			-- protect owner account
			return false, "Insufficient privileges!"
		end

		time = parse_time(time)
		if time < 60 then
			return false, "You must ban for at least 60 seconds."
		end
		local expires = os.time() + time

		-- is player already banned?
		local id = get_id(player_name)
		if id then
			if bans[id] then
				return true, ("%s is already banned!"):format(player_name)
			else
				local r = create_ban(player_name, name, reason, expires)
				if r then
					return true, ("Banned %s until %s."):format(
						player_name, os.date("%c", expires))
				end
			end
		end
	end,
})

-- Override default unban command
minetest.override_chatcommand("unban", {
	description = "Unban a player or ip banned with authx",
	params = "<player_or_ip> <reason>",
	privs = { ban = true },
	func = function(name, params)
		local name_or_ip, reason = params:match("(%S+)%s+(.+)")
		if not (name_or_ip and reason) then
		return false, "Usage: /unban <player_or_ip> <reason>"
		end
		-- look for records by id
		local id = get_id(name_or_ip)
		if id then
			if not bans[id] then
				return false, ("No active ban record for " .. name_or_ip)
			end
			local r = update_ban(id, name, reason, name_or_ip)
			if r then return true, ("Unbanned %s."):format(name_or_ip) end
		else -- check blacklist
			local key = name_or_ip
			if is_ip(key) then key = ip_key(key) end
			if BL[key] then
				local r = del_blacklist_entry(name_or_ip)
				if r then return true, ("Unbanned %s."):format(name_or_ip) end
			end
		end
	end,
})

-- Register whois command
minetest.register_chatcommand("/whois", {
	params = "<player> [v]",
	description = "Returns player information, use v for full record.",
	privs = {ban_admin = true},
	func = function(name, param)
		local list = {}
		for word in param:gmatch("%S+") do
			list[#list+1] = word
		end
		if #list < 1 then
			return false, "usage: /whois <player> [v]"
		end
		local pname = list[1]
		local id = get_id(pname)
		if not id then
			return false, "The player \"" .. pname .. "\" did not join yet."
		end
		local names = name_records(id)
		local ips = address_records(id)
		local msg = "\n" .. minetest.colorize("#FFC000", "Names: ")
		local n, a = {}, {}
		for i, v in ipairs(names) do
			n[#n+1] = v.name
		end
		for i, v in ipairs(ips) do
			a[#a+1] = v.ip
		end
		msg = msg .. table.concat(n, ", ")
		if #list > 1 and list[2] == "v" then
			msg = msg .. minetest.colorize("#FFC000", "IP Addresses: ")
			msg = msg .. "\n" .. table.concat(a, ", ")
		else
			msg = msg .. "\n" .. minetest.colorize("#FFC000", "Last IP Address: ")
			msg = msg .. a[1]
		end
		return true, minetest.colorize("#FFC000", "Info for: ") .. pname .. msg
	end,
})

-- Register whitelist command
minetest.register_chatcommand("wl", {
	description = "Manages the whitelist",
	params = "(add|del|list) <name_or_ip>",
	privs = {server = true},
	func = function(name, params)
		local helper = ("Usage: /ban_wl (add|del) "
		.."<name_or_ip> \nor /ban_wl list")
		local param = {}
		for word in params:gmatch("%S+") do
			param[#param + 1] = word
		end
		if #param < 1 then
			return false, helper
		end
		if param[1] == "list" then
			local str = ""
			for k, v in pairs(WL) do
				str = str..k.."\n"
			end
			if str ~= "" then
				return true, str
			end
			return true, "Whitelist empty!"
		end
		if param[2] then
			if param[1] == "add" then
				if not WL[param[2]] then
					local r = add_whitelist_entry(name, param[2])
					if r then
						WL[param[2]] = true
						minetest.log("action", (
							"%s added %s to whitelist"
						):format(name, param[2]))
						return true, param[2].." added to whitelist!"
					end
				else
					return false, param[2].." is already whitelisted!"
				end
			elseif param[1] == "del" then
				if WL[param[2]] then
					local r = del_whitelist_entry(param[2])
					if r then
						WL[param[2]] = nil
						minetest.log("action", ("%s removed %s from whitelist"
						):format(name, param[2]))
						return true, param[2].." removed from whitelist!"
					end
				else
					return false, param[2].." isn't on the whitelist"
				end
			end
		end
		return false, helper
	end
})

--[[
############################
###  Register callbacks  ###
############################
]]

-- Register auth handler
minetest.register_authentication_handler(authx.auth_handler)
-- Minetest registers auth handlers silently so log the event!
minetest.log('action', "[authx] now registered as the authentication handler")

-- Register callback for shutdown event
minetest.register_on_shutdown(function()
	db:close()
end)

-- Register callback for prejoin event
-- Note: triggers before auth handler
minetest.register_on_prejoinplayer(function(name, ip)

	local id
	local obj = auth_get(name)

	-- auth name check
	if obj then

		-- found db auth record
		-- ip address check
		local target_id = get_id(ip) -- fetch id for ip
		if not target_id then
			-- new ip record for this id
			add_ip(obj.id, ip)
		elseif obj.id ~= target_id then
			-- address registered to another id!
			-- log event in db
			manage_idv_record(obj.id, target_id, ip)
			update_idv_status(ip)
			update_address(target_id, ip) -- update record
		else
			update_address(obj.id, ip) -- update record
		end

	else

		-- name similarity check
		local chk = auth_check_name(name)
		if chk then
			-- reject client
			return ("\nCannot create new player called '%s'. "..
				"Another account called '%s' is already registered.\n"..
				"Please check the spelling if it's your account "..
				"or use a different name."):format(name, chk.name)
		end

		-- Init prejoin cache entry
		pjc[name] = {ip = ip, new = false}

		-- Fetch id, existing or new
		id = get_id(ip)
		if not id then
			id = inc_id()
			pjc[name].new = true
		end
		pjc[name].id = id -- init id entry

	end

	-- Blacklist check
	local bl = BL[name] or BL[ip_key(ip)]
	if bl then
		return 'Banned: Expires: end of time, Reason: ' .. bl.reason
	end

	-- Whitelist check
	if WL[name] or WL[ip] then
		minetest.log("action", (
			"[authx] %s authorised by whitelist entry"))
		return
	end

	if not debug and owner_id and owner_id == id then return end -- owner bypass

	local data = bans[id]
	if not data then
		-- Check names per id present in conf
		if names_per_id then
			-- names per id
			local names = name_records(id)
			-- ignore existing entries
			for _,v in ipairs(names) do
				if v.name == name then return end
			end
			-- check player isn't exceeding account limit
			if #names >= names_per_id then
				-- create string list
				local msg = {}
				for _,v in ipairs(names) do
					msg[#msg+1] = v.name
				end
				msg = table.concat(msg, ", ")
				return ("\nYou exceeded the limit of accounts ("..
				names_per_id..").\nYou already have the following accounts:\n"
				..msg)
			end
		end
		-- Check ip's per id present in conf
		if ip_limit then
			local t = address_records(id)
			for _,v in ipairs(t) do
				if v.ip == ip then return end -- ignore existing entries
			end
			if #t >= ip_limit then
				return "\nYou exceeded " .. ip_limit .. " ip addresses on this account!"
			end
		end

	else
		-- Check for ban expiry
		local date = "the end of time"

		if type(data.expires) == "number" and data.expires ~= 0 then
			-- Temp ban
			if os.time() > data.expires then
				-- clear temp ban
				update_ban(data.id, "authx", "ban expired", name)
				return
			end
			date = hrdf(data.expires)
		end

		return ("Banned: Expires: %s, Reason: %s"):format(date, data.reason)

	end
end)

-- Register callback for join event
minetest.register_on_joinplayer(function(player)
	-- Fetch name from the player obj
	local name = player:get_player_name()
	-- Add player to the hotlist
	add_hotlist_entry(name)
	trim_cache()
end)
