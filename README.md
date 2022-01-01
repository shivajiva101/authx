[![Build status](https://github.com/shivajiva101/authx/workflows/Check%20&%20Release/badge.svg)](https://github.com/shivajiva101/authx/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)


# authx

If you use sauth and sban then this mod is for you, it combines the functionality of both in
a single database, adding account restrictions based on number of accounts per id,
ip addresses per id, and naming restrictions like similarity and length.

It's a one stop solution for authenticating players with optional control.

#### INSTALLATION

authx requires lsqlite3 (https://github.com/LuaDist/lsqlite3).

If you have luarocks (https://luarocks.org/) installed on the target server,
you can easily install lsqlite3 in a terminal:

    luarocks install lsqlite3

If the target server runs mods in secure mode[recommended], you must add authx
to the list of trusted mods in minetest.conf:

	secure.trusted_mods = authx

#### COMMANDS

The mod provides the following chat console commands. These commands require
the ban privilege. The ban_admin and server privileges extend the functionality
of some commands.

#### bang

Launches the GUI. Comprehensive management of bans via a user interface for convenience.
On launch the interface shows a list containing the last 10 players to join. Use search
to find a player if they are not in the list. Multiple records are shown if available, by
using the arrows that appear.

``` Usage: /bang ```

<b>Please note</b> accessing the gui formspec using a modified client without serverside
privs is coded to ban the player

#### ban

Bans a player permanently.

``` Usage: /ban <name_or_ip> <reason> ```

Example: /ban Steve Some reason.

The server privilege enables the pre-emptive banning of player names or
IP addresses for which the server has no current record. This is achieved by adding
them to a separate table so the entries don't contaminate the actual records.

#### tempban

Bans a player temporarily.

```Usage: /tempban <name_or_ip> <time> <reason>```

Example: /tempban Steve 2D Some reason.

The time parameter is a string in the format \<count> \<unit>,
where \<unit>  is either s for seconds, m for minutes, h for hours, D for days,
W for weeks, M for months, or Y for years. If the unit is omitted, it is
assumed to mean seconds. For example, 42 means 42 seconds, 1337m means 1337 minutes,
and so on. You can chain more than one such group and they will add up.
For example, 1Y3M3D7h will ban for 1 year, 3 months, 3 days and 7 hours.

#### unban

Unbans a player.

```Usage: /unban <name_or_ip> <reason>```

Example: /unban Steve Some reason.

Note that this command requires a reason and works for pre-emptive bans

#### ban_record

Displays player record and ban record.

```Usage: /ban_record <name_or_ip>```

Example: /ban_record Steve

This prints the player record and ban record for a player. The records are
printed to the chat console with one entry per line.

The player record includes names and, if the user has the ban_admin privilege,
IP addresses used by the player. The number of records displayed is limited
to 10 by default to prevent chat console spam, and can be adjusted through
the authx.display_max setting in minetest.conf.

The ban record includes a list of all ban related actions performed on the player
under any known name or IP address. This includes the time a ban came into effect,
the expiration time (if applicable), the reason, and the source of the ban.

Note that the records of players with the server privilege can only be viewed
by other players with the server privilege.

#### ban_wl

Manages the whitelist.

```Usage: /ban_wl (add|del|list) <name_or_ip>```

Example: /ban_wl add Steve

Whitelisted players are allowed on the server even if they are marked
as banned. This is useful to ensure moderators cannot ban each other.

The add subcommand adds a player to the whitelist.
The del subcommand removes a player from the whitelist.
The list subcommand lists the players on the whitelist.

#### ADMINISTRATION COMMANDS

These commands are for administering the server and require the server privilege.
You can import a server's previous ban history from xban2's xban.db file or from
Minetest's ipban.txt file.

This is an intensive process that will cause server lag, so it's recommended
you perform this on a local instance and copy the database to the server
before starting with the authx mod installed.

#### ban_dbi

Imports bans from xban.db or ipban.txt files into an existing
auth.sqlite file.

```Usage: /ban_dbi <filename>```

Example: /ban_dbi xban.db or /ban_dbi ipban.txt

It's possible to place multiple files in the world folder and execute the
command on each file. For example:

    /ban_dbi xban_1.db
    /ban_dbi xban_2.db

Each record is checked against the database by player name to prevent duplicate
entries.

#### ban_dbe

Extracts all valid player records from an xban.db file and saves them in xban.sql.

```Usage: /ban_dbe <input_filename>```

Example: /ban_dbe xban.db

This creates a file called xban.sql in the world folder. Import the file
from the sqlite prompt using:

    .open authx.sqlite
    .read xban.sql
    .exit

The time of the import operation is dependant on the size of the .sql file.

#### ban_dbx

Dumps the database back to xban2 file format. Use it before you uninstall this mod
if you intend using xban2 and wish to retain the data.

```Usage: /ban_dbx```

Do this before enabling xban2 mod otherwise it will be overwritten by the currently loaded data.

#### whois

```Usage: //whois <name> [v]```

Example: //whois sadie

Returns all known accounts and the last ip addresses associated with a player name.
Use the v option to get the list of ip addresses (display_max still limits amount displayed)
#### CONFIG

You can add these optional settings to minetest.conf to adjust the authx mod's
behaviour.

#### auth.api

Controls loading of the API functions. Default is false.

	authx.api = true

This would load the API functions and allow other mods access via the global authx table.

#### authx.display_max

Changes the maximum number of player records displayed when using the /ban_record
command.

	authx.display_max = 12

This would increase the number of records shown from the default 10 records to 12.

#### authx.ban_max

Allows server owners to set an expiry date for bans. It uses the same format for
durations as the /tempban command.

	authx.ban_max = 90D

In this example all permanent player bans created after the setting has been added
to minetest.conf, and after a server restart, will expire 90 days after the ban was
set. If required, longer ban durations can still be set with the tempban command.

Please note that if you delete or adjust the setting, after restarting the server, bans
created while the setting was active will not change and will retain their original
expiry date.

#### authx.accounts_per_id

Restricts accounts a player can make with an id.

	authx.accounts_per_ip = 5

Please note this is optional and without the setting the player accounts are unrestricted.

#### authx.addresses_per_id

Restricts number of addresses a player can use with an id.

	authx.addresses_per_id = 10

Please note this is optional and without the setting the player accounts are unrestricted.

#### authx.import_enabled

Disables the import/export sections of code.

	authx.import_enabled = false

The default is true, this setting allows you to save memory by disabling the code and commands associated with
importing & exporting data and should only be set to false once you have imported any ban sources.

#### authx.cache.max

Maximum cached name records.

	authx.cache.max = 1000

If you don't add this setting authx will use the value above as the default.

#### authx.cache.ttl

Time in seconds to deduct from the last player to login as the cutoff point for pre caching names.

	authx.cache.max = 86400

If you don't add this setting authx will use the value above as the default. Disable name caching by setting to -2


#### CREDITS

Thanks to:

