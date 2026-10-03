"""Bundled common-word stop-list for known values (spec 015 "Sync behaviour").

A synced single-word value on this list never becomes a known value, whatever its
label: tokenizing "May" or "Support" everywhere would wreck ordinary text. Casefolded;
English and Dutch. Words under 3 characters are left out (the length rule drops them).
"""
from __future__ import annotations

_WORDS = """
the and but for nor yet not all any some none each every both either neither this that these those
there here then than when where what which who whom whose why how you your yours our ours their theirs
his her hers its him she they them one two three four five six seven eight nine ten first last next
will may might can could shall should would must did does done has have had was were are been being
get got let say see use new old big top low high best good bad more most less least very just only
also still even ever never now today yesterday tomorrow day week month year time date
january february march april june july august september october november december
monday tuesday wednesday thursday friday saturday sunday
januari februari maart mei juni juli augustus oktober
maandag dinsdag woensdag donderdag vrijdag zaterdag zondag
yes true false null nil n/a none unknown undefined empty blank default other others misc various
general test testing demo example sample dummy temp todo tbd tba placeholder
admin administrator root system support info information sales service services contact contacts
office home main private personal business company customer customers client clients user users
guest anonymous noreply no-reply team staff member members group account billing invoice order
active inactive open closed pending new draft deleted archived
mark bill rose grace hope joy faith summer autumn winter spring
het een van voor met niet geen wel ook maar door naar over onder tussen bij uit tot als dan
nee onbekend overig overige algemeen klant klanten bedrijf thuis kantoor privé zakelijk
"""
STOP_WORDS = frozenset(_WORDS.split())
