# Tools Help
This readme is designed to help you use the sql files in the tools folder.


Each file has a particular use case defined as follows:

<b>export_auth.sql</b>


Use this file to copy authx auth table data into Minetest auth database. It should be used if you want to stop using authx mod and would like the records transferring back.


<b>import_auth.sql</b>


Use this file if you are not using sauth or sban mods. It will copy the necessary
data from Minetest's own auth database.


<b>import_authsban.sql</b>


Use this file if your setup was using just the sban mod. It will copy Minetest auth  data and sban data to authx database.


<b>import_authsban.sql</b>


Use this file if your setup was using both sauth & sban mods. It will copy data from sauth database and sban database into the authx database.

# Correct Use Of The Files
To correctly apply one of these files to the authx database you need to use Sqlite3.
Firstly copy the file you want to use to the world folder, backup the database you are about to modify and then launch a terminal
from that location. Use Sqlite3 like this to apply the sql file of your choice:

```  
sqlite3 authx.sqlite
.read <your_choice>.sql
.exit 
```
There is no guarantee you won't corrupt data if you apply any of these files more than once to a database so always backup first!