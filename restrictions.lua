--[[
authx mod for Minetest designed and coded by shivajiva101@hotmail.com

The code in this file originates from names_restrictions mod by ShadowNinja
which was released under WTFPL.

]]

local exemptions = {}
local msg_guest = "Guest accounts are disallowed on this server.  "..
		"Please choose a proper name and try again."
local msg_misleading = "Your player name is misleading.  "..
		"Please choose a more appropriate name."
local disallowed = {
	["^guest[0-9]+"] = msg_guest,
	["^squeakecrafter[0-9]+"] = msg_guest,
	["adm[1il]n"] = msg_misleading,
	["[0o]wn[e3]r"]  = msg_misleading,
	["^[0-9]+$"] = "All-numeric usernames are disallowed on this server.",
}
local similar_chars = {
	-- Only A-Z, a-z, 1-9, dash, and underscore are allowed in player names
	"A4",
	"B8",
	"COco0",
	"Ee3",
	"Gg69",
	"ILil1",
	"S5",
	"Tt7",
	"Zz2",
}
local min_name_len, char_map, all_chars, owner
char_map = {}
owner = minetest.settings:get("name")

-- Map of characters to a regex of similar characters
for _, str in pairs(similar_chars) do
	for c in str:gmatch(".") do
		if not char_map[c] then
			char_map[c] = str
		else
			char_map[c] = char_map[c] .. str
		end
	end
end

for c, str in pairs(char_map) do
	char_map[c] = "[" .. char_map[c] .."]"
end

-- Characters to match for, containing all characters
all_chars = "["
for _, str in pairs(similar_chars) do
	all_chars = all_chars .. str
end
all_chars = all_chars .. "]"

-- Exempt server owner
exemptions[owner] = true

min_name_len = tonumber(minetest.settings:get("authx.minimum_name_length")) or 3

local function parse_name_exemptions()
	local temp = minetest.settings:get("authx.name.exemptions")
	temp = temp and temp:split() or {}
	for _, allowed_name in pairs(temp) do
		exemptions[allowed_name] = true
	end
end
parse_name_exemptions()

minetest.register_on_prejoinplayer(function(name,ip)

	if exemptions[name] then return end -- exemption bypass

	-- Check for disallowed names
	local lname = name:lower()
	for regx, reason in pairs(disallowed) do
		if lname:find(regx) then
			return reason
		end
	end

	-- String off dashes and underscores from the start and end of the name.
	local stripped_name = name:match("^[_-]*(.-)[_-]*$")
	if not stripped_name or stripped_name == "" then
		return "Your name is composed solely of whitespace-like characters."
	end

	-- Generate a regular expression to match all similar names
	local re = stripped_name:gsub(all_chars, char_map)
	re = "^[_-]*" .. re .. "[_-]*$"

	for authName in pairs(authx.auth_handler.iterate) do -- luacheck: ignore
		if authName ~= name and authName:match(re) then
			return "Your name is too similar to another player's name."
		end
	end

	-- Check name length
	if #name < min_name_len then
		return "Your player name is too short, please try a longer name."
	end
end)
