import cpp

from MacroInvocation mi
where mi.getMacroName().regexpMatch("ntoh.*")
select mi, "network functions call"
