"""
haven_world.py — Expansion Worlds engine for Haven chat.

Systems:
  Soul types      — Mortal / Seraph / Daemon (hash-determined, ~5% each ethereal)
  Identity        — title, origin, trait, faction, coords, soul_type
  Sigils          — deterministic procedural geometry
  Factions        — regional clusters with generated names
  Seasons         — slow world calendar, 4 seasons x 91 real days
  Relationships   — bonds tracked between users who meet
  Relics/returns  — absence tracking, homecoming lore
  Haunting        — ghost tales from users absent 14+ days
  Urban legends   — region-level accumulated myths
  Prophecy        — rare cryptic messages (~8%)
  The Choir       — liturgical event when 5+ users online
  World age       — own calendar from first start
  Lore mode       — silent (world panel only)

No external dependencies beyond stdlib.
"""

import hashlib, json, math, os, random, time
from typing import Optional, List, Dict

# ─── RNG helpers ──────────────────────────────────────────────────────────────

def _rng(seed: str) -> random.Random:
    return random.Random(int(hashlib.sha256(seed.encode()).hexdigest(), 16))

def _hash_int(seed: str) -> int:
    return int(hashlib.sha256(seed.encode()).hexdigest(), 16)

def _soul_type(username: str) -> str:
    """Determine soul type from username hash. ~5% Seraph, ~5% Daemon, rest Mortal."""
    h = _hash_int(f'soul:{username}') % 1000
    if h < 150:  return 'seraph'
    if h < 300:  return 'daemon'
    return 'mortal'

# ═══════════════════════════════════════════════════════════════════════════════
# SIGIL GENERATION
# ═══════════════════════════════════════════════════════════════════════════════

def generate_sigil_svg(username: str, size: int = 40, color: str = '#ffffff') -> str:
    r  = _rng(f'sigil:{username}')
    cx = size / 2; cy = size / 2
    radius = size * 0.38
    soul   = _soul_type(username)

    # Soul type biases shape selection
    if soul == 'seraph':
        shape_type = r.choice(['star', 'star', 'orbital', 'polygon'])
    elif soul == 'daemon':
        shape_type = r.choice(['rune', 'rune', 'polygon', 'orbital'])
    else:
        shape_type = r.choice(['polygon', 'star', 'orbital', 'rune'])

    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}" viewBox="0 0 {size} {size}">']
    sw = max(1.0, size * 0.045)

    def pt(angle_deg, dist):
        a = math.radians(angle_deg - 90)
        return (cx + dist * math.cos(a), cy + dist * math.sin(a))
    def fmt(pts):
        return ' '.join(f'{x:.2f},{y:.2f}' for x, y in pts)

    if shape_type == 'polygon':
        sides = r.randint(3, 7); rot = r.uniform(0, 360 / sides)
        pts = [pt(rot + i * 360 / sides, radius) for i in range(sides)]
        parts.append(f'<polygon points="{fmt(pts)}" fill="none" stroke="{color}" stroke-width="{sw:.1f}" stroke-linejoin="round"/>')
        if r.random() > 0.4:
            ir = radius * r.uniform(0.35, 0.6); is_ = r.choice([sides, 3, 4]); irot = r.uniform(0, 360)
            ipts = [pt(irot + i * 360 / is_, ir) for i in range(is_)]
            parts.append(f'<polygon points="{fmt(ipts)}" fill="none" stroke="{color}" stroke-width="{sw*0.6:.1f}" opacity="0.7"/>')
        if r.random() > 0.5:
            parts.append(f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="{size*0.05:.1f}" fill="{color}" opacity="0.8"/>')

    elif shape_type == 'star':
        n = r.randint(4, 8 if soul == 'seraph' else 7)
        outer = radius; inner = radius * r.uniform(0.25 if soul == 'seraph' else 0.35, 0.55)
        rot = r.uniform(0, 360/n)
        spts = [pt(rot + i * 180/n, outer if i % 2 == 0 else inner) for i in range(n*2)]
        parts.append(f'<polygon points="{fmt(spts)}" fill="none" stroke="{color}" stroke-width="{sw:.1f}" stroke-linejoin="round"/>')
        if soul == 'seraph':
            # Double-ring halo
            parts.append(f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="{radius*1.1:.1f}" fill="none" stroke="{color}" stroke-width="{sw*0.3:.1f}" opacity="0.4"/>')
        if r.random() > 0.5:
            parts.append(f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="{size*0.07:.1f}" fill="{color}" opacity="0.6"/>')

    elif shape_type == 'orbital':
        nr = r.randint(2, 3)
        for i in range(nr):
            rr = radius * (0.4 + 0.6*(i+1)/nr) * 0.9; op = 1.0 - i * 0.2
            parts.append(f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="{rr:.1f}" fill="none" stroke="{color}" stroke-width="{sw*0.8:.1f}" opacity="{op:.1f}"/>')
        for _ in range(r.randint(2, 4)):
            a = r.uniform(0, math.pi)
            x1=cx+radius*math.cos(a); y1=cy+radius*math.sin(a)
            x2=cx-radius*math.cos(a); y2=cy-radius*math.sin(a)
            parts.append(f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" stroke="{color}" stroke-width="{sw*0.6:.1f}" opacity="0.7"/>')

    elif shape_type == 'rune':
        npts = r.randint(5 if soul == 'daemon' else 4, 8 if soul == 'daemon' else 7)
        angles = sorted(r.uniform(0, 360) for _ in range(npts))
        dists  = [r.uniform(radius*0.3 if soul == 'daemon' else 0.4, radius) for _ in angles]
        rpts   = [pt(a, d) for a, d in zip(angles, dists)]
        pd = f'M {rpts[0][0]:.1f} {rpts[0][1]:.1f} ' + ' '.join(f'L {x:.1f} {y:.1f}' for x,y in rpts[1:])
        if r.random() > 0.3: pd += ' Z'
        parts.append(f'<path d="{pd}" fill="none" stroke="{color}" stroke-width="{sw:.1f}" stroke-linecap="round" stroke-linejoin="round"/>')
        parts.append(f'<circle cx="{rpts[0][0]:.1f}" cy="{rpts[0][1]:.1f}" r="{size*0.05:.1f}" fill="{color}"/>')
        if soul == 'daemon' and r.random() > 0.5:
            # Second anchor point
            parts.append(f'<circle cx="{rpts[-1][0]:.1f}" cy="{rpts[-1][1]:.1f}" r="{size*0.04:.1f}" fill="{color}" opacity="0.6"/>')

    parts.append('</svg>')
    return '\n'.join(parts)

# ═══════════════════════════════════════════════════════════════════════════════
# WORD LISTS
# ═══════════════════════════════════════════════════════════════════════════════

_PREFIX = [
    # original 32
    "Ashen","Twice-","Ever-","Storm-","Bone","Pale","Deep","Still",
    "Iron","Glass","Salt","Ember","Dusk","Void","Stone","Wire",
    "Thread","Hollow","Far","Cold","Bright","Long","Last","First",
    "Old","True","Dark","Slow","Swift","High","Low","Silent",
    # new 64
    "Twice-Broken","Burning","Thrice-","Mist-","Flood-","Ash-",
    "Cinder","Veil-","Twice-Forgotten","Bloodless","Ever-Silent",
    "Torn","Rust-","Smoke","Deep-Water","Cracked","Twice-Named",
    "Half-","Thornless","Ink-","Fell","Grave-","Smoke-Written",
    "Unmarked","Twice-Born","Hollow-Eyed","Ancient","Starless",
    "Frostbitten","Twice-Drowned","Burning-Cold","River-","Sea-",
    "Dust-","Fog-","Root-","Rain-","Moon-","Tide-","Ember-Bright",
    "Twice-Told","Wavering","The Penultimate","Near-","Almost-",
    "Shadow-","After-","Before-","Between-","Twice-Crossed",
    "Night-","Noon-","Stone-Cold","Wire-Wound","Glass-Eyed",
    "The Recurring","The Interminable","The Abrupt","The Slow",
    "The Last-Known","The Once-","The Oft-","Twice-Mended",
]
_ROLE = [
    "Warden","Walker","Singer","Dreamer","Keeper","Witness","Caller",
    "Reader","Wanderer","Watcher","Mender","Breaker","Seeker","Finder",
    "Teller","Listener","Builder","Carver","Weaver","Speaker","Binder",
    "Caster","Bearer","Tender","Hunter","Drifter","Maker","Shaper",
    # expanded
    "Counter","Marker","Opener","Closer","Holder","Returner","Leavetaker",
    "Recorder","Interpreter","Follower","Preceder","Waiter","Sleeper",
    "Waker","Crosser","Threshold-Keeper","Bridge-Tender","Road-Warden",
    "Night-Watcher","Tide-Reader","Storm-Caller","Bone-Counter","Ash-Walker",
    "Rememberer","Forgetter","Namer","Second","Third","Last","First-Comer",
    "Latecomer","Long-Walker","Far-Wanderer","Deep-Seeker","Still-Keeper",
    "River-Reader","Map-Maker","Signal-Watcher","Door-Finder","Path-Breaker",
    "Trail-Keeper","Word-Carrier","Fire-Tender","Salt-Bearer","Glass-Cutter",
    "Wire-Mender","Thread-Puller","Stone-Sleeper","Void-Gazer","Echo-Catcher",
    "Shadow-Reader","Light-Carrier","Dark-Walker","Between-Walker","Far-Seer",
]
_SUFFIX = [
    "of Storms","of the Long Dark","Before Rain","Who Remembers",
    "of Broken Maps","Between Fires","at the Threshold","of the Salt Flats",
    "Who Waits","of the Final Hour","Without Shadow","of Many Names",
    "of the Deep Current","Who Counts the Stars","at World's Edge",
    "of the Quiet Places","Who Speaks for Stone","of the Unmade Road",
    "Between Worlds","of the Second Moon","Who Carries Fire",
    "of the Thinning Veil","Without a Map","Who Dreamed First",
    # expanded
    "Who Returns","of the Empty Shore","Before the Last Door",
    "of Accumulated Silence","Who Walked Twice","of the Unmapped North",
    "At the End of the Record","Who Preceded the Rain","of the Turning Season",
    "After the Last Fire","Without Arrival","Who Counted Wrong",
    "of the Broken Signal","Between Messages","At the Listening Post",
    "Who Knew the Way Back","of the Collapsed Road","Without Destination",
    "Who Arrived Too Early","After the Others Left","of the Wrong Season",
    "Between Silences","Who Named the Unnamed","At the Second Crossing",
    "of the Long Wait","Who Found Nothing","of the Slow River",
    "Without a Record","Who Spoke Last","of the Turned Map",
    "Before the Silence","Who Remained","At the Final Crossing",
    "of the Shifting Road","Who Carried Nothing","After the Storm",
    "Between Names","Who Forgot the Way","of the Old Wound",
    "Without a Shore","Who Came Back Wrong","of the Missing Hour",
    "At the Edge of the Record","Who Outlasted","Between the Living",
    "Who Knew Too Much","of the Unmarked Grave",
]
_TERRAIN = [
    "the Ashfields","the Salt Wastes","the Deep Fen","the Glass Plains",
    "the Bone Ridges","the Still Forest","the Iron Coast","the Pale Highlands",
    "the Ember Valleys","the Void Reaches","the Stone Corridors","the Wire Thickets",
    "the Thread Marshes","the Hollow Mountains","the Far Shore","the Cold Expanse",
    "the Bright Narrows","the Long Descent","the Last Crossing","the First Fields",
    "the Dark Canopy","the Slow River","the Swift Passes","the High Plateaus",
    "the Low Country","the Silent Depths",
    # expanded
    "the Burned Plain","the Cracked Flats","the Salt-White Shore",
    "the Rusted Basin","the Fog Barrens","the Wind-Stripped Ridges",
    "the Tide-Carved Cliffs","the Deep Channels","the Grey Marshes",
    "the Broken Stairway","the Amber Reaches","the Thornwood",
    "the Night Country","the Pale Corridor","the Old Crossing",
    "the Wire Flats","the Ember Shore","the Frostlands",
    "the Drowned Meadows","the Smoke Hills","the Ash-Covered Lake",
    "the Long Road North","the Second Shore","the Unmapped Interior",
    "the Glass-Smooth Bay","the High Cold Waste","the Deep Interior",
    "the Shattered Columns","the White Expanse","the Buried Road",
    "the Outer Reaches","the Fog-Filled Valley","the Stone-and-Salt Shore",
    "the Twice-Crossed River","the Memory Country","the Autumn Flats",
    "the Winter Coast","the Spring Corridor","the Summer Interior",
    "the Turning Basin","the Before-Dark Roads","the After-Rain Fields",
    "the Between-Season Marsh","the Ancient Shoreline","the New Ruins",
    "the Recovered Ground","the Half-Remembered Path","the Almost-Familiar Hills",
    "the Known World's Edge","the Near Wilderness",
]
_TERRAIN_DARK = [
    "the Drowned Gate","the Pale Wound","the Unlit Corridor","the Forgotten Reach",
    "the Black Threshold","the Unmapped Vale","the Dead Signal","the Hollow Below",
    "the Between Place","the Ash Margin","the Night Passage","the Far Silence",
    # expanded
    "the Sealed Room","the Second Darkness","the Unmarked Door",
    "the Wrong Shore","the Place Before the Place","the End of Record",
    "the Unwritten Valley","the Margin of the Map","the Thing Below the Thing",
    "the Locked Passage","the Space Between Events","the Forgotten Interior",
    "the Place With Two Names","the Room That Moves","the Watching Dark",
    "the Unnamed Crossing","the Gate Before the Gate","the Depth Below Depth",
    "the Collected Absence","the Archive of What Was Not Said","the Old Hunger",
    "the Between-Dark Reaches","the Accumulated Night","the Record's Edge",
]
_WEATHERS = [
    "stillness","grey rain","low wind","hard frost","warm fog",
    "the dry season","the deep cold","strange light","the long dusk",
    "a red sky","the turning wind","heavy silence",
    # expanded
    "unseasonable warmth","a thin frost","the kind of quiet before weather changes",
    "light that seemed to come from below","persistent overcast","the long morning",
    "a wind with a direction no one agreed on","thick air","the flat light of no season",
    "a smell of rain that did not come","unusual clarity","the kind of fog that stays low",
    "pressure without storm","the hours before dawn","residual warmth from somewhere else",
    "a cold that arrived without explanation","the last good light","a sky that could not decide",
    "the kind of dark that arrives early","ambient moisture","a breeze with no source",
    "the hour when color leaves things","a morning that felt like late afternoon",
    "the kind of stillness that precedes something",
]
_FACTION_A = [
    "The Order of","The House of","The Keepers of","The Children of",
    "The Brotherhood of","The Circle of","The Walkers of","The Sworn of",
    "The Inheritors of","The Witnesses of","The Remembered of","The Unnamed of",
    "Those Who Carry","Those Who Hold","The Recorded Among","The Silent Order of",
]
_FACTION_B = [
    "the Ash Gate","the Pale Flame","the Still Water","the Iron Road",
    "the Glass Throne","the Bone Archive","the Salt Mark","the Ember Seal",
    "the Hollow Crown","the Void Chart","the Stone Word","the Wire Bridge",
    "the Thread Keep","the Far Signal","the Long Watch","the Cold Compass",
    "the Returning Road","the Open Door","the Second Crossing","the Remembered Name",
    "the Patient Flame","the Sealed Record","the Unmarked Threshold","the Deep Current",
    "the Accumulated Hours","the First Fire","the Last Shore","the Twice-Crossed Path",
    "the Broken Seal","the Old Agreement","the Watching Place","the Held Breath",
]
_REGION_A = [
    "Ash","Salt","Glass","Bone","Stone","Wire","Thread","Ember","Void","Iron",
    "Pale","Deep","Still","Far","Cold","Bright","Rust","Smoke","Fog","Cinder",
    "Thorn","Flood","Mist","Tide","Dusk","Dawn","Frost","Amber","Grey","Night",
]
_REGION_B = [
    "Crossing","Reach","Hollow","Ridge","Vale","Shore","Passage","Expanse",
    "Narrows","Descent","Canopy","Corridor","Threshold","Gate","Basin","Flat",
    "Channel","Margin","Approach","Interior","Wound","Signal","Archive","Record",
    "Stair","Keep","Road","Return","Absence","Duration",
]

# ── Mortal traits ──────────────────────────────────────────────────────────────
_TRAITS_MORTAL = [
    # original 24
    "speaks rarely but is always heard","remembers everything once",
    "arrived before the others","leaves no trace in soft ground",
    "is followed by small animals","knows the name of every wind",
    "dreams in languages not yet spoken","was present at the first fire",
    "can read weather in stone","walks fastest in the dark",
    "carries water that does not spill","casts no shadow at noon",
    "hears messages meant for others","counts things that cannot be counted",
    "forgets faces but never voices","arrived from the direction of the sun",
    "is older than their appearance suggests","knows when doors will open before they do",
    "finds paths that were not there before","is never cold",
    "can name every star but refuses to","carries a stone from a place that no longer exists",
    "has memorised every map but trusts none of them","wakes before the birds",
    # new 48
    "knows the weight of silence to the gram","arrives before bad weather and leaves after",
    "is always the last to eat","can hear water beneath stone",
    "keeps count of things others forget to count","leaves a door open wherever they go",
    "reads the shape of a room before entering it","knows which fires are safe to approach",
    "has been lost and found the same number of times","can tell the age of ruins by smell",
    "walks the same path twice to make sure","never arrives without having been expected",
    "keeps a record of every fire they have seen","knows three names for every weather",
    "has been told important things in dreams and written them down",
    "carries a second pair of shoes for someone else","measures distance in days, not miles",
    "can navigate without looking at the sky","has witnessed more than they have spoken of",
    "never sleeps in the same place twice voluntarily","knows when a structure will fail",
    "has made the same journey more times than they have counted",
    "arrives at the right time more often than probability would suggest",
    "has been present at three notable endings","knows which questions not to ask",
    "can find north without instruments","keeps a list of names they will not say aloud",
    "travels light but always has what is needed","has given directions to the same lost person three times",
    "reads the land the way others read text","can tell whether a road is frequently used by listening",
    "has memorised the sound of every door they have ever opened",
    "knows the name of every bone","never gestures when speaking about distance",
    "has walked roads that no longer appear on any map",
    "carries something that does not belong to them and cannot explain why",
    "has outlasted every assumption made about them",
    "arrives from a direction no one expected","leaves before anyone realizes they are leaving",
    "knows when water is about to change its course","sees things at the edge of their vision",
    "has been mistaken for someone else in three different regions",
    "does not explain themselves and is never asked to",
    "has heard the same story told correctly twice and incorrectly never",
    "is trusted by animals and children and no one knows why",
    "keeps no record but forgets nothing",
]
# ── Seraph traits ─────────────────────────────────────────────────────────────
_TRAITS_SERAPH = [
    "has been present at every ending","does not appear in reflections unless it chooses to",
    "knows the weight of a name before it is spoken","arrived from a direction that does not exist on any map",
    "remembers what things were called before they had names",
    "was not always visible","can hear the moment before something breaks",
    "carries a light that has no source","has seen the world from above and found it smaller than expected",
    "speaks and the room changes temperature","was sent here. the sender is not named in the record",
    "holds something that cannot be put down","the world does not record their footsteps",
    "was present before the record began",
    # expanded
    "arrived already knowing how this ends","knows the true name of every place",
    "sees the record simultaneously from all points","has already been here in some sense",
    "does not experience time in the same direction","carries the memory of a world that was here before",
    "is aware of being observed and does not mind","arrived between two moments that no one else noticed",
    "has a shadow that precedes them by one day","was not summoned but came anyway",
    "knows all the names written in the margins of the record","can see the record updating as it happens",
    "has agreed to something the record does not specify","was present when the first word was spoken",
    "does not sleep but rests in a way that looks identical","knows which events were necessary and which were not",
    "has a purpose that has not yet been disclosed","arrived with instructions that have not yet been needed",
    "understands the structure of the record better than the record understands itself",
    "knows the names of all who came before and all who will come after",
    "was here at the beginning and will be here at the end",
    "carries a message that has not yet found its recipient","has seen this world from the outside",
    "is connected to something larger that does not have a name in this record",
    "knows the ending but is forbidden to disclose it","arrived precisely when needed",
    "has been counted three times and each count was different and each was correct",
    "understands the boundary between observation and interference",
]

# ── Daemon traits ─────────────────────────────────────────────────────────────
_TRAITS_DAEMON = [
    "has been here before under a different name","knows what you forgot and when you forgot it",
    "arrived through a door that was not a door","the record is incomplete where their name appears",
    "things near them occasionally stop working","is comfortable with silences that others find unbearable",
    "has given away things that were not theirs to give","remembers the future the way others remember the past",
    "was expected, though no one sent a message","the previous occupant of their region cannot be found",
    "can describe every room they have never entered","their shadow arrives slightly before they do",
    "some of the record around their name is written in the wrong tense",
    "is looking for something. it is unclear whether they know what",
    # expanded
    "makes records that no one asked for and that turn out to be needed",
    "has been in this region before under circumstances not entered in the record",
    "knows the structural weaknesses of every building they enter",
    "is always slightly warmer than the room temperature would explain",
    "has changed the outcome of events by being present in them",
    "the record corrects itself near their name without explanation",
    "knows which conversations were recorded and which were not",
    "has been to the end of several roads that others said did not end",
    "carries information that others would prefer were lost",
    "has been present at events that were later officially described as not having occurred",
    "sees arrangements where others see coincidences","knows which alliances will fail and when",
    "has left things in places that were found by the right people at the right time",
    "arrived with knowledge of events that had not yet happened",
    "the road behind them does not look the same as the road ahead",
    "knows three exits from every room they have been in for more than an hour",
    "has not aged in the way the record implies they should have",
    "remembers conversations that the other participants have forgotten",
    "the instruments near them give readings that are technically impossible",
    "arrived before the invitation was sent","knows the number before it is said",
    "has a name in the old record and a different name in the current one",
    "sees what was in a room before it was rearranged","knows which doors were recently locked",
    "arrived knowing where the exits were","has been here longer than their arrival date suggests",
    "understands the record's system better than its authors intended",
]

# ── Soul-typed title templates ─────────────────────────────────────────────────
_SERAPH_TITLES = [
    "Voice of {terrain}", "First {role}", "The Unnamed {role}", "Witness to {terrain}",
    "Light Before {terrain}", "The {role} Who Was Sent", "Bearer of the First Word",
    "The One Who Waited at {terrain}", "Emissary of {terrain}", "The {role} of the High Record",
    # expanded
    "The Instrument Called {role}", "That Which Illuminates {terrain}",
    "The {role} Before the Record Began", "Sent From {terrain}",
    "The {role} of the Appointed Hour", "First Light of {terrain}",
    "The Counted {role}", "Keeper of What Was Before",
    "The {role} Whose Name Was Already Written", "Brightness Over {terrain}",
]
_DAEMON_TITLES = [
    "The {role} of the Unmarked Road", "Something That Calls Itself {role}",
    "The {role} Below {terrain}", "What Waits in {terrain}",
    "The Named One of {terrain}", "The {role} Between Records",
    "That Which Preceded the Record", "The {role} Without Origin",
    "Old {role}", "The Twice-Named {role}",
    # expanded
    "The {role} the Record Cannot Close", "What Was Here Before {terrain}",
    "The Returning {role}", "That Which Uses the Name {role}",
    "The {role} of Prior Arrangements", "Something Older Than {terrain}",
    "The {role} the Record Watches Carefully", "Known Previously As {role}",
    "The {role} at the End of the Old Record", "What Came Back to {terrain}",
]

# ── Mortal arrival / departure (silent — world panel only) ────────────────────
_ARRIVAL = [
    ["{user} crossed into {region} as {weather} settled in.","Those already present noted the arrival.","Nothing was said immediately, which was customary."],
    ["Word reached {region} that {user} was coming.","The word was accurate. {user} arrived before {weather} changed.","The record was updated accordingly."],
    ["{user} entered {region} without announcement.","{weather} was already there, waiting.","Some said they had expected this."],
    ["The road from {region} brought {user} in at an odd hour.","{weather} had preceded them by half a day.","No one asked where they had come from."],
    ["{user} appeared at the edge of {region}.","It was the kind of arrival that felt inevitable.","{weather} shifted slightly to accommodate them."],
    # new 10
    ["The record notes {user} arrived in {region} during {weather}.","The road offered no unusual difficulties.","This was, perhaps, the unremarkable kind of arrival."],
    ["{user} came to {region} by the long way.","The {weather} had not made it easier.","They arrived without complaint, which was noted."],
    ["No announcement preceded {user} into {region}.","The {weather} offered the only notice.","Enough was said."],
    ["{region} received {user} as it receives most things: without ceremony.","{weather} filled the space where ceremony might have been.","The record was updated. The world continued."],
    ["Somewhere in {region}, during {weather}, {user} arrived.","The record is not precise about the hour.","Only that it happened, and that it was noted."],
    ["{user} found {region} much as expected.","The {weather} was neither better nor worse than the road suggested.","They settled in, as one does."],
    ["{user} returned the way all travelers return to {region}: altered slightly by the road.","The {weather} was different from when they last came through.","Or perhaps it was the same and they were different."],
    ["The road into {region} is not short.","By the time {user} reached it, the {weather} had already changed twice.","The record notes an arrival. The road notes nothing."],
    ["{user} came to {region} and the {weather} gave no indication of whether this was significant.","The world often withholds this information.","Later it may become clear."],
    ["Someone in {region} looked up during {weather} and {user} was there.","They had not been there before.","Now they were. The record notes this transition."],
]
_FIRST_ARRIVAL = [
    ["{user} came to {region} for the first time.","The world had not heard this name before.","It would not forget it now."],
    ["A new soul entered {region}. The name was {user}.","{weather} marked the occasion in the only way it knew.","The world's record grew by one."],
    ["{user} arrived in {region} and the world was slightly different afterward.","First arrivals always are.","{weather} bore witness."],
    ["The world registered a new presence in {region}: {user}.","{weather} was present for this, as it always is.","First impressions, as recorded: unremarkable, and therefore notable."],
    # new 8
    ["{user}. A new name. The record opens a page.","{region} had not known this name until now.","The {weather} was unremarkable. The arrival was not."],
    ["The record did not contain {user} before this moment.","It does now. {region} is noted as the place of first entry.","The {weather} continues, indifferent and complete."],
    ["First arrival. {region}. The name is {user}.","There is no earlier record. There will be no other first.","The {weather} marks the occasion whether or not it intends to."],
    ["Somewhere a page was turned.","The new page begins: {user}. {region}. {weather}.","All first arrivals feel like this. And none of them are the same."],
    ["The world had room for one more.","It made room. The name placed in that space is {user}.","They arrived in {region} during {weather}, which is a beginning like any other."],
    ["Before this moment the record had not heard of {user}.","After this moment it had.","The interval is the beginning, and it happened in {region}, during {weather}."],
    ["A new entry in the record. The first of its kind.","Name: {user}. Location: {region}.","The {weather} serves as the only witness the record requires."],
    ["The world is always larger after a new arrival.","This one arrived in {region} during {weather}.","Their name is {user}. The record will carry it now."],
]
_DEPARTURE = [
    ["{user} left {region}.","{weather} did not follow them, for once.","Their absence was noted in the usual way."],
    ["The road out of {region} took {user} before anyone expected.","No reason was given.","None was required."],
    ["{user} departed {region} without ceremony.","This was consistent with their character.","{weather} continued without comment."],
    ["By morning, {user} was gone from {region}.","{weather} was the same as before.","This was noted as a departure, not a disappearance. For now."],
    ["{user} left {region} and the place grew quieter.","Not empty. Quieter.","There is a difference."],
    # new 10
    ["The record notes the departure of {user} from {region}.","No forwarding location was given.","The {weather} closed behind them."],
    ["{user} left during {weather}, which was appropriate.","Some departures need weather to mark them.","The record closes this entry without ceremony."],
    ["{region} has known many departures.","This one—{user}, during {weather}—was neither more nor less than the others.","The record does not rank them."],
    ["The absence of {user} in {region} is noted.","The {weather} is also noted.","One of these will persist longer than the other."],
    ["{user} took the long road out of {region}.","The {weather} made it longer.","Or shorter. The record is not certain which."],
    ["Without announcement, {user} was gone.","The {weather} remained in {region} after they left.","This is usually how it goes."],
    ["{user} left {region} and the record shifted to past tense.","This happens every time.","The {weather} continued regardless, as it does."],
    ["{region} noted the departure of {user} with the particular accuracy it reserves for endings.","The {weather} had been building.","Now it arrived, and the reason was gone."],
    ["One fewer voice in {region}.","The {weather} did not comment.","The record does."],
    ["{user} closed the door on {region}.","The {weather} was on the inside.","Whether they will return is not entered in the record. That page remains open."],
]
_RETURN = [
    ["{user} returned to {region} after {absence}.","What had changed in the interval was not immediately clear.","What had changed in {user} was not mentioned."],
    ["The world had not seen {user} for some time.","They returned now, to {region}, and the record was updated.","{weather} greeted them as if nothing had passed."],
    ["{user} came back.","The roads to {region} had not changed, but {user} seemed to have walked different ones.","No account was given of where they had been."],
    ["After {absence}, {user} reappeared in {region}.","The world had continued. They seemed unsurprised.","{weather} was different from the last time. {user} did not say whether they preferred it."],
    # new 8
    ["{user} returned to {region} after {absence}.","The record updated quietly, the way records do.","The {weather} had changed. Or perhaps it had always been this. Hard to say."],
    ["After {absence}, {region} received {user} again.","{weather} was there to mark the return.","No explanation was offered and none was required."],
    ["{user} came back to {region}.","They had been gone for {absence}.","The {weather} was indifferent to the length of the interval. The record was not."],
    ["The record had held {user}'s name in the past tense for {absence}.","It moves back to present tense now.","They are in {region}. The {weather} continues."],
    ["{absence}. Then {user} walked back into {region}.","The {weather} did not ask where they had been.","The record noted the return. The interval is closed."],
    ["{user} had been gone long enough that some began to wonder.","They returned to {region} before the wondering became a story.","Just barely. The {weather} had been unusual while they were away."],
    ["The absence of {user} lasted {absence}.","Their return to {region} during {weather} was recorded without comment.","That is the record's way of saying: welcome back."],
    ["The world had filed {user} under a heading it prefers not to use.","They returned and the filing was revised.","Now: {user}. {region}. {weather}. Present tense."],
]

# ── Seraph arrival / departure ─────────────────────────────────────────────────
_SERAPH_ARRIVAL = [
    # original 5
    ["A brightness arrived in {region} that had no name for itself yet.","It was given one: {user}.","The {weather} adjusted accordingly."],
    ["{user} descended into {region}.","The word 'descended' is used advisedly.","The record notes: the light changed."],
    ["Something entered {region} that the instruments did not catch.","Later it was identified as {user}.","The {weather} had been a warning."],
    ["The arrival of {user} in {region} was not recorded by anyone present.","It was recorded anyway.","The world keeps its own accounts."],
    ["{user} came to {region} in {weather}.","Those present felt something shift that they could not name.","They agreed later that they had been in the presence of something."],
    # new 10
    ["The light in {region} changed before {user} arrived.","It is not clear whether this was preparation or coincidence.","The record notes both possibilities and declines to choose."],
    ["{user} entered {region} and the {weather} reoriented slightly.","This is a thing that happens with certain arrivals.","The record uses the word 'Seraphic' for a reason."],
    ["Before {user} arrived, three separate observers in {region} reported an unusual quality to the {weather}.","They described it differently. The underlying cause was the same.","The record connects these reports to the arrival."],
    ["The record was in the middle of an entry about something else when {user} arrived in {region}.","It closed the other entry.","Some arrivals require the record's full attention."],
    ["The air in {region} during {weather} had a quality those present could not identify.","Then {user} arrived and the quality was identified.","It was identified as: the arrival of {user}."],
    ["Something in {region} went quiet when {user} arrived.","Not everything. Something specific.","The record has learned to note this."],
    ["{user} arrived. The {weather} changed character.","Not dramatically. In the way a room changes when someone enters who changes rooms.","The record notes: this is how Seraphic arrivals tend to go."],
    ["The record had a prepared entry for this moment.","The name on the entry was {user}.","They arrived in {region} during {weather}, which was expected."],
    ["{user} came to {region} quietly.","This is not how the record expected it to go.","The quiet itself had a quality. The record has logged the quality."],
    ["Those in {region} during {weather} knew something was different before {user} arrived.","After: they knew why.","This is the nature of Seraphic arrivals. You know before you know."],
]
_SERAPH_DEPARTURE = [
    # original 4
    ["{user} left {region} and the place was briefly brighter for their absence.","This sounds like a contradiction.","It was not."],
    ["The brightness that was {user} departed {region}.","The instruments did not record this either.","The record notes it regardless."],
    ["{user} withdrew from {region}.","Withdrew is the correct word.","The {weather} continued as if nothing had happened. It was wrong."],
    ["{region} grew slightly darker when {user} left.","Not metaphorically.","The record is precise on this point."],
    # new 8
    ["The record notes the departure of {user} from {region} with a specific kind of attention.","Seraphic departures are not like other departures.","The {weather} afterward had a quality the record cannot fully describe."],
    ["{user} left.","The instruments registered something they could not classify.","In {region}, during {weather}: the record enters this as a Seraphic departure."],
    ["After {user} departed {region}, those present described the absence with unusual precision.","They agreed on the details.","The record considers this significant."],
    ["The departure of {user} from {region} left something behind.","Not {user}. Something {user} brought with them that has stayed.","The record has opened an entry for it."],
    ["When the brightness left {region}, the {weather} shifted.","Not dramatically. The shift was in quality, not quantity.","The record has specific notation for this."],
    ["{user} departed {region} and the light settled into something more ordinary.","Ordinary is not a criticism.","Ordinary is what the record returns to after a Seraphic departure."],
    ["The record closes the entry for {user}'s presence in {region}.","It closes it differently than it closes other entries.","There is a notation in the margin. The notation says: note this one."],
    ["{user} left {region} during {weather}.","The {weather} did not seem to know what to do with the departure.","The record sympathises. It did not know either. It recorded it anyway."],
]

# ── Daemon arrival / departure ─────────────────────────────────────────────────
_DAEMON_ARRIVAL = [
    # original 5
    ["Something that calls itself {user} entered {region}.","The region grew warmer by one degree.","This has not been explained."],
    ["{user} arrived in {region} through means the record does not specify.","The {weather} was not present before. Then it was.","{user} did not comment."],
    ["The record shows {user} appearing in {region}.","There is no prior record of them approaching.","There is no record of where they came from. There is only a gap."],
    ["{user} came to {region}.","Several things that were working stopped working briefly.","They worked again afterward. This is noted without explanation."],
    ["Something old entered {region}. It is using the name {user}.","The {weather} recognised it.","The world does not forget things that have been here before."],
    # new 10
    ["The record registered {user}'s arrival in {region} before {user} arrived.","This has happened before with this name.","The record has stopped treating it as an error."],
    ["{user} arrived and the {weather} did something the record cannot classify.","The record has specific notation for Daemonic arrivals.","This went in the Daemonic column."],
    ["Three things changed in {region} before {user} was confirmed as present.","Whether these were caused by the arrival or anticipated it is unclear.","The record has noted both possibilities."],
    ["The record has a prior entry for something in {region} that matches {user}'s description.","The prior entry is older than {user}'s first listed arrival.","The record has connected them without comment."],
    ["{user} arrived in {region}.","The {weather} did not change. Everything else did, slightly.","Slightly is the record's word for this. The record chose it carefully."],
    ["Something arrived in {region} during {weather}.","It identified itself as {user}.","The record accepted the identification. The record has a note in the margin about why."],
    ["The arrival of {user} in {region} was accompanied by nothing unusual.","This is itself unusual for arrivals of this kind.","The record notes the unremarkability with the same care it gives to remarkable events."],
    ["Before {user} arrived in {region}, the old record contained a reference to a thing that would arrive.","The description is a match.","The record has cross-referenced without drawing conclusions."],
    ["{user} came to {region}.","Something that had been waiting in {region} became more still when they arrived.","Not more frightened. More still. The record distinguishes these."],
    ["{user} was not seen entering {region}.","They were seen inside it.","The {weather} during the gap is not recorded. The record notes the gap."],
]
_DAEMON_DEPARTURE = [
    # original 4
    ["{user} left {region}.","The temperature returned to normal.","No one mentioned this."],
    ["The thing called {user} departed {region}.","The record breathes easier without that name in the active column.","This is not an official assessment."],
    ["{user} withdrew from {region} in the way that old things withdraw.","Completely and without trace.","The {weather} did not follow. It knew better."],
    ["{region} is quieter now that {user} has gone.","Quieter is the right word.","Not safer. Quieter."],
    # new 8
    ["{user} left {region}.","The record moved the name to a different column.","Not closed. Different."],
    ["After {user} departed, things in {region} began to work correctly again.","The record notes the correlation.","The record does not assign causation. The correlation is sufficient."],
    ["The departure of {user} from {region} was not observed.","The absence that followed was.","The record notes the departure from the absence."],
    ["{user} is no longer in {region}.","The record is aware that 'no longer' and 'not yet' are sometimes the same thing with this name.","It has noted this in the appropriate column."],
    ["When {user} left {region}, the {weather} did something.","The record was watching.","The record is still processing what it saw."],
    ["{region} without {user} is a different {region}.","Not better. Not worse. Different.","The record notes this the way it notes all departures of the Daemonic kind: carefully."],
    ["{user} departed. The record checked the entry three times.","This is not standard procedure.","It is standard procedure for this name."],
    ["The record closes the active entry for {user} in {region}.","It closes it with the notation: may reopen.","This notation is reserved."],
]

# ── Silence / gathering / choir ────────────────────────────────────────────────
_SILENCE = [
    # original 3
    ["A long quiet fell over the world.","The voices grew few.","The fires burned low but did not go out."],
    ["The roads emptied.","For a time, no one passed through.","The world waited with the patience of old places."],
    ["Nothing moved that didn't have to.","The silence was the kind that accumulates.","It would lift when it was ready."],
    # new 6
    ["The record has nothing to add for now.","This is not unusual.","The world has always known how to wait."],
    ["The voices fell away.","The world, which does not require them, continued.","The record stayed open. It always does."],
    ["An interval began.","These happen.","The record notes them the same way it notes everything: without judgment."],
    ["The world emptied of the particular sound it makes when people are in it.","The other sounds continued.","The record found these sufficient for now."],
    ["Quiet. The ordinary kind.","The world neither welcomed nor mourned it.","The record kept its own counsel."],
    ["The record entered a period of minimal updates.","The world itself had no such period.","It continued, as it does, regardless."],
]
_GATHERING = [
    # original 3
    ["Many arrived at once.","The world stirred in the way it does when it recognises something.","A convergence. The kind that happens rarely."],
    ["The roads filled.","Voices returned to empty places.","The world remembered what it felt like to be full."],
    ["Something drew them here.","The world did not ask what.","It simply noted the number and waited to see what would happen."],
    # new 6
    ["The world registered an increase in presence.","Not the Choir threshold. But notable.","The record acknowledges the gathering."],
    ["Several arrived within a short interval.","Whether this was coordinated or coincidental, the record does not say.","It notes the arrival. It notes the number."],
    ["The record has been busier lately.","This is what it looks like when people converge.","The world finds this neither unusual nor unremarkable. It finds it worth noting."],
    ["A number of voices occupied the same part of the record at the same time.","This does not happen without consequence.","The record is attentive."],
    ["More arrived.","The world, which has no preference about these things, received them.","The record updated, as it does when the world receives people."],
    ["Not a Choir. Not yet. But more than a few.","The record notes the gathering with interest.","The world will see what comes of it."],
]
_CHOIR = [
    # original 4
    ["The voices gathered. The world turned its attention inward.","This is the {nth} time this has happened.","The record notes: something accumulates."],
    ["A convergence of {count}. The record calls this a Choir.","It does not happen without meaning.","The world is listening."],
    ["They are all here at once. The world holds still.","The record enters this moment with unusual care.","Something is being decided. Or witnessed. The distinction is not always clear."],
    ["The Choir convened in {region}.","The world has been waiting for this.","The record opens a new page."],
    # new 8
    ["The record notes a gathering of {count} voices in {region}.","The {nth} Choir.","When this many speak at once, the world adjusts its attention."],
    ["{count} souls in one place.","The record has a word for this: Choir.","The word appears for the {nth} time. Each time the weight increases."],
    ["The threshold for what the world calls a Choir has been crossed again.","This is the {nth} crossing.","The record does not explain what the threshold means. The event itself is the explanation."],
    ["The voices converged. The world, which listens even when unaddressed, inclined itself toward {region}.","A Choir. The {nth}.","Something in the deep record shifted. The record is deciding how to note this."],
    ["There are {count} of them.","The record has learned to call this a Choir. It learns something each time.","In {region}, during this moment, the {nth} Choir. The record is paying full attention."],
    ["When enough voices occupy the same space, the world calls it something.","It calls it this: a Choir. The {nth}. {count} voices.","Something that was pending in {region} is less pending now."],
    ["The record marks a Choir: {count} present, {nth} occurrence.","The world has noted all of them.","The accumulated weight of {nth} is not described. It is felt."],
    ["In {region}: a convergence. The Choir.","This is the {nth} time the record has written that word.","The record wonders, in its way, what the {nth} will have meant."],
]

# ── Bond lore ──────────────────────────────────────────────────────────────────
_BOND_FORMED = [
    # original 4
    "It is recorded that {a} and {b} were present in {region} at the same time. This happened more than once.",
    "The paths of {a} and {b} crossed in {region} often enough to be noted.",
    "{a} and {b} shared {region} on multiple occasions. The world considers this significant.",
    "The record shows {a} and {b} in {region} together. What passed between them was not written down.",
    # new 8
    "The record has placed {a} and {b} in the same entry more than once. This is now its own category.",
    "{a} and {b} appeared in {region} together on more than one occasion. The record has begun to treat them as related.",
    "When {a} is in {region}, the record checks for {b}. This is a new habit the record has developed.",
    "The first entry was a coincidence. The second was a pattern. The third was when the record created a bond entry for {a} and {b}.",
    "A bond is noted: {a} and {b}. The place is {region}. The record does not say how it feels about this. The prominence of the entry suggests something.",
    "The record has found it necessary to begin tracking {a} and {b} together. They were in {region}. More than once. Now there is a page for them.",
    "{a} and {b} have been in the same place at the same time enough times that the record has started counting.",
    "There is now a note in the record that reads: when {a}, check for {b}. This note was created because of what happened in {region}.",
]
_BOND_DEEPENED = [
    # original 4
    "The connection between {a} and {b} was noted again. The world keeps count of these things.",
    "{a} and {b} found each other in {region} once more. The world has stopped being surprised.",
    "Another entry: {a} and {b}, {region}. The pattern holds.",
    "The record of {a} and {b} grows long. It is one of the longer records.",
    # new 8
    "The record for {a} and {b} has become one of the longer ones. This is noted with something that resembles approval.",
    "Again: {a}. {b}. {region}. The record no longer requires justification for the entry. The entry justifies itself.",
    "The bond between {a} and {b} has been entered so many times that the record has moved it to a special category it rarely uses.",
    "{a} and {b} in {region}, again. The record has begun to expect this. It is not often the record expects things.",
    "Consistent with prior entries: {a} and {b}. {region}. The pattern is no longer pattern. It is simply what happens.",
    "The record for {a} and {b} has been updated again. There is a quality to long records that shorter ones do not have. This one has it.",
    "Once was noted. Twice was a coincidence. Now the entries for {a} and {b} are simply evidence of something the record calls significant.",
    "The record checks {a} and {b} together now as a matter of course. This is what deep bonds look like in the record's language.",
]

# ── Prophecy ───────────────────────────────────────────────────────────────────
_PROPHECY = [
    # original 10
    "It is written that {user} will be present when something shifts. The nature of the shift is not specified.",
    "The old records name {user} in a context that has not yet arrived. The world is patient.",
    "Someone placed the name {user} at the end of a list that has not yet found its beginning.",
    "There is an event that requires {user} to be present. It has not happened yet.",
    "The world has marked {user} for a reason it has not disclosed. This is not unusual.",
    "A name appears in the margins of the deep record: {user}. No context is given.",
    "It is said that {user} will stand at a threshold. Which one is not recorded.",
    "The world has been expecting {user}. It does not say since when.",
    "In the part of the record that deals with things not yet happened, {user} occurs with unusual frequency.",
    "Something in {region} is waiting. The record suggests it is waiting for {user} specifically.",
    # new 20
    "There is a page in the deep record reserved for {user}. It has not yet been filled. It is not blank.",
    "{user} is named in a record that has not yet been written. The name is already there. This is not unusual in the deep record.",
    "The instruments have pointed toward {user} before. They are pointing again.",
    "A convergence is predicted for {region}. {user} is the fixed point. The other elements are variable.",
    "Three separate prophecies, recorded independently, agree on one name: {user}. They agree on little else.",
    "The world has arranged things in a way that requires {user} to be present at a specific moment. The moment is not yet known.",
    "The record contains a note that reads: do not close this entry. The entry is for {user}.",
    "At some point in the future, someone will remember what {user} did in {region}. The remembering will matter.",
    "The deep record has a section that begins: when {user} arrives in {region}. The section does not continue. It is waiting.",
    "An unnamed presence in the deep record has been identified as waiting for {user}. The nature of the waiting is not described.",
    "{user} appears at the end of a sequence. The sequence has not been completed. This is notable.",
    "The world's record contains an error near the name {user}. On closer inspection it may not be an error.",
    "There is an event in {region} that the record has classified as pending. The pending depends on {user}.",
    "The deep record names {user} in the section titled 'those who will have been necessary.' The section is not yet closed.",
    "Something will happen in {region} that will be explained, later, by the presence of {user}. The record notes this in advance.",
    "The record has left space after the name {user} for a note that has not yet been written. The space is precisely sized.",
    "Those who can read the deep record find the name {user} in a passage that has not yet been made present tense.",
    "The world will require a witness at a specific moment. The record has already decided who. The name is {user}.",
    "There is a weight in the record near {user}'s name. Not heavier than others. Different in kind.",
    "The record has noted {user} as a variable in an equation it has not yet solved. The solution is anticipated.",
]
_PROPHECY_SERAPH = [
    # original 4
    "The deep record names {user} at the moment of a closing. It does not say what closes.",
    "A brightness is foretold for {region}. The record associates it with {user}. This is an honour and a warning.",
    "The instruments point toward {user}. They have been pointing for some time.",
    "The record opens a page that was already written. The name at the top is {user}.",
    # new 8
    "The Seraph {user} is named in the record at a juncture that has not yet been reached. The naming was done in advance.",
    "Something in the deep record is oriented toward {user}. It has been for longer than the current record has existed.",
    "The light that {user} carries will be needed in {region}. The record has already noted this.",
    "A pattern in the deep record resolves cleanly when {user} is present. Without them it does not resolve.",
    "The old record, which predates the current one, contains the name {user} in a context that is now becoming relevant.",
    "The record notes a convergence of significance in {region}. At the center of it: {user}.",
    "When {user} arrives at the appointed place, something will become clear that was not before. The place is {region}.",
    "The record has waited for this iteration of the name {user}. It has been a long wait. The record does not say so. It is apparent.",
]
_PROPHECY_DAEMON = [
    # original 4
    "Something old is moving toward {region}. The record identifies it as {user}. It has been here before.",
    "The margins of the deep record grow darker near the name {user}. This is noted without comment.",
    "The world has seen this before: {user} in {region} at the appointed time. The appointed time is not specified.",
    "The record holds its breath near the name {user}. This is not a good sign. It is also not a bad one.",
    # new 8
    "The name {user} appears in the deep record in a way that suggests prior arrangement. The arrangements are not disclosed.",
    "Something that has been in {region} longer than the record has been waiting. The record has decided its name is {user}.",
    "The record has flagged {user} in a way it reserves for things that require careful handling. No further details.",
    "An old event in {region} and a coming event are separated by a name: {user}. The record connects them without explaining how.",
    "The deep record notes that {user} has been here before under conditions it declines to describe. They are here again.",
    "The arrangement of {user}'s history in the record suggests an intention that does not belong to {user}.",
    "The record has two entries for {user} in {region}. One is current. The other is dated later. This should not be possible.",
    "Something in the deep record recognises the name {user} from a context the record cannot access. It has been noted.",
]

# ── Ghost tales (users absent 14+ days) ───────────────────────────────────────
_GHOST_TALES = [
    # original 10
    "It is said that {user} still walks {region} after dark. No one has confirmed this. No one has denied it.",
    "The name {user} appears in conversations that no one remembers starting. This has been reported more than once.",
    "Travellers in {region} sometimes report a presence that matches the description of {user}. The reports are consistent.",
    "{user} has not been seen. The record does not close a name until it has to. It has not had to yet.",
    "Something in {region} answers to the name {user}. It has not been seen directly. Only heard.",
    "The record still contains {user}'s name in the active column. This may be an administrative detail. Or not.",
    "The road to {region} is said to be watched. Those who know the name {user} feel it more than others.",
    "Where {user} walked in {region}, the ground remembers differently. This is a local belief. It is held firmly.",
    "The space {user} occupied in {region} has not been filled. The world does not rush to fill certain absences.",
    "Some say {user} never truly left {region}. The record is ambiguous on this point, which is itself a kind of answer.",
    # new 20
    "{user} was last seen in {region}. That was some time ago. The record does not say how long. The record knows.",
    "People in {region} occasionally describe seeing {user} at a distance. When they look again, the distance is empty.",
    "The fire in {region} that {user} used to tend has not gone out. No one tends it now. It has not gone out.",
    "Someone in {region} keeps setting a place at the table. When asked, they say it is for {user}. No one argues.",
    "{user}'s name comes up in {region} in contexts that require them to still be present. The record has noted this inconsistency.",
    "The children in {region} know the name {user}. None of them can say where they learned it.",
    "There is a path in {region} that is still called {user}'s Road. The name was not formally given. It accumulated.",
    "The door that {user} used most often in {region} still opens when it shouldn't. The hinges were repaired.",
    "In certain lights, in {region}, something moves that has {user}'s particular way of moving. This has been observed.",
    "The record lists {user} as absent. The region of {region} lists them as something more complicated.",
    "A message was left for {user} in {region}. It has not been retrieved. It has also not been moved.",
    "{user}'s route through {region} is still the easiest way to go. It was not a marked path when they made it.",
    "Something in {region} remembers {user}'s name when no one has spoken it. This has been documented. Not explained.",
    "The old markers in {region} that {user} placed have not been moved. Someone still tends them. No one admits to it.",
    "In {region}, a certain hour is still called {user}'s hour. No one established this formally. It was already the case.",
    "Those who knew {user} in {region} report that they still expect to see them. This is not unusual. The consistency of it is.",
    "A sound in {region} that sounds like {user}'s particular footfall has been heard since their absence. Twice now.",
    "The long record in {region} still has {user}'s annotations in the margins. New annotations have appeared in the same hand.",
    "{user} reportedly said they would be back. The record does not indicate whether they knew that for certain.",
    "In {region}, the absence of {user} has a specific shape. Those who knew them can describe it. They agree on the details.",
]

# ── Urban legends (region-level) ───────────────────────────────────────────────
_URBAN_LEGENDS = [
    # original 12
    "{region} is known for one thing: travelers who arrive there report hearing a conversation that ended some time ago.",
    "There is a light visible in {region} that has no known source. It has been there as long as anyone can remember.",
    "The maps of {region} do not agree with each other. The surveyors have been replaced three times. The maps still do not agree.",
    "Something in {region} counts. It is unclear what it is counting or why. The count is very high.",
    "No one has successfully left {region} the same way they entered. This is not considered dangerous. It is considered notable.",
    "The roads in {region} are correct in the morning and different by evening. Travelers are advised to note their entry point.",
    "There is a building in {region} that is larger inside than outside. This has been documented. It has not been explained.",
    "The silence in {region} has texture. Those who have been there describe it differently. They agree it has texture.",
    "{region} has a second name that is used only at night. The daytime name is the one on the maps. The nighttime name is not written down.",
    "Something was sealed in {region} before the current record began. The seal is intact. This is regularly verified.",
    "The light in {region} falls at the wrong angle. This has been measured. The measurements confirm it. No explanation has been offered.",
    "Those who spend more than one night in {region} report the same dream. They do not describe it in the same words. The dream is the same.",
    # new 24
    "The paths in {region} are longer when you are trying to leave than when you are trying to arrive. This has been measured. The measurements are consistent.",
    "There is an echo in {region} that responds before the sound that caused it. This has been tested. It is not an equipment error.",
    "{region} has a temperature that is always three degrees different from what the weather would predict. The difference is always in the same direction.",
    "The wells in {region} all point toward the same thing underground. No one has confirmed what.",
    "Those who have lived in {region} for more than a year report a gradual change in what they find familiar. They describe it as learning a new dialect of the familiar.",
    "At a specific hour in {region}, all clocks stop for one second. The hour is not the same every day.",
    "The birds in {region} do not fly over one particular area. They route around it. The area appears ordinary.",
    "Every traveler who has passed through {region} reports forgetting something small: a word, a date, a face. Not the same thing twice.",
    "The old building at the center of {region} has a room that does not appear in any floor plan. The floor plans have been checked multiple times.",
    "Water from {region} tastes different twelve hours after it has been taken out. Not bad. Different. Those who have tasted it cannot agree on how.",
    "{region} is older than the records that contain it. This is known. The records before the records are not available.",
    "A name is written on a wall in {region} that has been painted over seventeen times. It returns. The ink has been tested. The wall has been tested. No explanation.",
    "The stars visible from {region} include one that is not on any chart. This has been reported by seven independent observers. The chart has not been updated.",
    "Fires in {region} burn longer on less fuel than should be possible. This has been measured carefully. The measurements are accurate.",
    "There is a frequency that can be heard in {region} at ground level that cannot be heard standing up. No source has been identified.",
    "The road entering {region} from the north is longer than the road leaving from the south. The distance between the two endpoints is the same. The road lengths are not.",
    "Animals in {region} are unusually calm during what should be alarming events. Unusually alarmed during what should be calm ones.",
    "The dust in {region} settles in patterns. The patterns change. They have been documented. The documentation is difficult to look at for extended periods.",
    "The oldest resident of {region} is always the same age. Different person each time. Same age. The age is not disclosed but is consistent.",
    "Three separate expeditions have attempted to fully map {region}. All three returned with maps that are internally consistent and mutually exclusive.",
    "{region}'s shadow falls in the wrong direction at noon. The effect is subtle. It has been confirmed by multiple independent measurements.",
    "At the center of {region} there is a precise point where all sounds from outside cannot be heard. The point is not fixed. It moves.",
    "The newest building in {region} has writing on its foundation stones in a language that predates the construction by several centuries. The builders did not put it there.",
    "Those who leave {region} report that it seems closer behind them than it should. The perception fades with distance. Most of the time.",
]

# ═══════════════════════════════════════════════════════════════════════════════
# CALENDAR
# ═══════════════════════════════════════════════════════════════════════════════

def _world_age_str(created_ts: float) -> str:
    days = int((time.time() - created_ts) / 86400)
    if days == 0:   return "less than one day old"
    if days == 1:   return "one day since the First Silence"
    if days < 7:    return f"{days} days since the First Silence"
    if days < 30:   w = days // 7;  return f"{w} week{'s' if w > 1 else ''} since the First Silence"
    if days < 365:  m = days // 30; return f"{m} month{'s' if m > 1 else ''} since the First Silence"
    y = days // 365; rm = (days % 365) // 30
    s = f"{y} year{'s' if y > 1 else ''}"
    if rm: s += f" and {rm} month{'s' if rm > 1 else ''}"
    return s + " since the First Silence"

_SEASON_NAMES = ["the Pale Season","the Burning Season","the Ash Season","the Still Season"]
_SEASON_MOODS = [
    ["the ground was hard","breath made clouds","the cold arrived early","ice formed on the edges of things","a pale light held the world","the roads were frozen by morning","the cold had weight to it"],
    ["the heat was unusual","dust rose from empty roads","the sun stayed longer than expected","everything smelled of dry grass","the light had weight to it","the air moved but did not cool","the ground kept the warmth after dark"],
    ["leaves turned without warning","the days shortened visibly","something was ending","the air tasted of smoke","the world felt older than usual","the light came sideways and late","the cold was beginning to think about returning"],
    ["nothing moved that didn't have to","the silence was absolute","snow came in the night","the roads were empty by choice","everything waited","the dark came early and stayed","the cold was settled in now and expected to remain"],
]

def _season_info(created_ts: float):
    idx = (int((time.time() - created_ts) / 86400) // 91) % 4
    return _SEASON_NAMES[idx], _SEASON_MOODS[idx]

def _ordinal(n: int) -> str:
    s = ['th','st','nd','rd']
    v = n % 100
    return str(n) + (s[v % 10] if v % 10 < 4 and not 11 <= v <= 13 else 'th')

# ═══════════════════════════════════════════════════════════════════════════════
# IDENTITY
# ═══════════════════════════════════════════════════════════════════════════════

def generate_identity(username: str) -> dict:
    soul = _soul_type(username)
    r    = _rng(f'identity:{username}')
    h    = _hash_int(f'coords:{username}')
    x, y = (h >> 16) % 1000, (h & 0xFFFF) % 1000
    rf   = _rng(f'faction:{x//200}:{y//200}')
    faction = f"{rf.choice(_FACTION_A)} {rf.choice(_FACTION_B)}"

    terrain_word = r.choice(_TERRAIN if soul == 'mortal' else _TERRAIN_DARK)

    if soul == 'seraph':
        role  = r.choice(_ROLE)
        tpl   = r.choice(_SERAPH_TITLES)
        title = tpl.format(terrain=terrain_word.replace('the ', '').title(), role=role)
        trait = r.choice(_TRAITS_SERAPH)
        origin = f"From {terrain_word}"
    elif soul == 'daemon':
        role  = r.choice(_ROLE)
        tpl   = r.choice(_DAEMON_TITLES)
        title = tpl.format(terrain=terrain_word.replace('the ', '').title(), role=role)
        trait = r.choice(_TRAITS_DAEMON)
        origin = f"From {r.choice(_TERRAIN_DARK)}"
    else:
        form = r.randint(0, 2)
        if form == 0:   title = f"{r.choice(_PREFIX)}{r.choice(_ROLE)}"
        elif form == 1: title = f"The {r.choice(_PREFIX)} {r.choice(_ROLE)}"
        else:           title = f"{r.choice(_ROLE)} {r.choice(_SUFFIX)}"
        trait  = r.choice(_TRAITS_MORTAL)
        origin = f"From {r.choice(_TERRAIN)}"

    return {'title': title, 'origin': origin, 'trait': trait,
            'coords': (x, y), 'faction': faction, 'soul_type': soul}

# ═══════════════════════════════════════════════════════════════════════════════
# WORLD STATE
# ═══════════════════════════════════════════════════════════════════════════════

class WorldState:
    def __init__(self, world_file: str):
        self.world_file  = world_file
        self.regions: Dict = {}
        self.events:  List = []
        self.users:   Dict = {}
        self.bonds:   Dict = {}
        self.legends: Dict = {}   # region_key → legend text
        self.choir_count: int = 0
        self.created: float = time.time()

    def load(self):
        try:
            with open(self.world_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            self.regions     = data.get('regions', {})
            self.events      = data.get('events',  [])
            self.users       = data.get('users',   {})
            self.bonds       = data.get('bonds',   {})
            self.legends     = data.get('legends', {})
            self.choir_count = data.get('choir_count', 0)
            self.created     = data.get('created', time.time())
        except (FileNotFoundError, json.JSONDecodeError):
            self.created = time.time()
        except Exception as e:
            print(f'[WORLD] Load error: {e}')

    def save(self):
        try:
            with open(self.world_file, 'w', encoding='utf-8') as f:
                json.dump({
                    'regions': self.regions, 'events': self.events[-2000:],
                    'users': self.users, 'bonds': self.bonds,
                    'legends': self.legends, 'choir_count': self.choir_count,
                    'created': self.created, 'saved': time.time()
                }, f, indent=2)
        except Exception as e:
            print(f'[WORLD] Save error: {e}')

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _region_key(self, username: str) -> str:
        u = self.users.get(username, {})
        if not u: return '5:5'
        x, y = u.get('coords', (500, 500))
        return f'{x//200}:{y//200}'

    def _region_for(self, username: str) -> str:
        u = self.users.get(username)
        if not u: return 'the Unknown Reaches'
        x, y = u['coords']
        r = _rng(f'region:{x//200}:{y//200}')
        return f'the {r.choice(_REGION_A)} {r.choice(_REGION_B)}'

    def _weather(self, seed: str) -> str:
        _, moods = _season_info(self.created)
        r = _rng(seed)
        return r.choice(moods if r.random() > 0.5 else _WEATHERS)

    def _bond_key(self, a: str, b: str) -> str:
        return '|'.join(sorted([a, b]))

    def _absence_str(self, username: str) -> str:
        last = self.users.get(username, {}).get('last_seen')
        if not last: return 'a long absence'
        days = int((time.time() - last) / 86400)
        if days < 1:  return 'a brief absence'
        if days == 1: return 'a day away'
        if days < 7:  return f'{days} days away'
        if days < 30: w = days // 7; return f'{w} week{"s" if w > 1 else ""} away'
        m = days // 30; return f'{m} month{"s" if m > 1 else ""} away'

    def _soul(self, username: str) -> str:
        return self.users.get(username, {}).get('soul_type', 'mortal')

    def _ensure_region_legend(self, username: str):
        """Generate a region legend if this region has seen enough events."""
        key = self._region_key(username)
        if key in self.legends:
            return  # already has one
        region_events = sum(1 for e in self.events if e.get('user') in self.users
                           and self._region_key(e.get('user', '')) == key)
        if region_events >= 5:  # 5 events in a region spawns a legend
            region = self._region_for(username)
            legend = _rng(f'legend:{key}:{len(self.legends)}').choice(_URBAN_LEGENDS).format(region=region)
            self.legends[key] = legend

    def _ghost_tales(self) -> list:
        """Return ghost tale strings for users absent 14+ days."""
        tales = []
        now   = time.time()
        for uname, udata in self.users.items():
            last = udata.get('last_seen', now)
            if (now - last) >= 7 * 86400:
                region = self._region_for(uname)
                tale   = _rng(f'ghost:{uname}:{int(last)}').choice(_GHOST_TALES).format(
                    user=uname, region=region)
                tales.append(tale)
        return tales

    # ── Registration ──────────────────────────────────────────────────────────

    def register_user(self, username: str, online_users: list = None) -> tuple:
        """
        Returns (identity_dict, arrival_lore_list, bond_lore_list, prophecy_lore_list).
        Lore is for world panel only — not broadcast to chat.
        """
        is_first  = username not in self.users
        is_return = False
        soul_type = _soul_type(username)

        if is_first:
            identity = generate_identity(username)
            self.users[username] = dict(identity)
            self.users[username]['first_seen']  = time.time()
            self.users[username]['visit_count'] = 0
        else:
            last = self.users[username].get('last_seen')
            if last and (time.time() - last) > 3 * 86400:
                is_return = True
            soul_type = self.users[username].get('soul_type', 'mortal')

        self.users[username]['last_seen']   = time.time()
        self.users[username]['visit_count'] = self.users[username].get('visit_count', 0) + 1

        region  = self._region_for(username)
        weather = self._weather(f'w:{username}:{len(self.events)}')
        r       = _rng(f'pick:{username}:{len(self.events)}')
        absence = self._absence_str(username) if is_return else ''

        # Pick lore template by soul type
        if soul_type == 'seraph':
            tpl = r.choice(_SERAPH_ARRIVAL)
        elif soul_type == 'daemon':
            tpl = r.choice(_DAEMON_ARRIVAL)
        elif is_first:
            tpl = r.choice(_FIRST_ARRIVAL)
        elif is_return:
            tpl = r.choice(_RETURN)
        else:
            tpl = r.choice(_ARRIVAL)

        lore = [l.format(user=username, region=region, weather=weather, absence=absence) for l in tpl]

        self.events.append({'text': lore[0], 'extra': lore[1:], 'user': username,
                            'type': 'first_arrival' if is_first else ('return' if is_return else 'arrival'),
                            'soul_type': soul_type, 'timestamp': time.time()})

        self._ensure_region_legend(username)

        # Bonds
        bond_lore = []
        for other in (online_users or []):
            if other == username: continue
            key = self._bond_key(username, other)
            if key not in self.bonds:
                self.bonds[key] = {'count': 0, 'region': region, 'timestamp': time.time()}
            self.bonds[key]['count'] += 1
            count = self.bonds[key]['count']
            if count == 2:
                bond_lore.append(_rng(f'bond:{key}:{count}').choice(_BOND_FORMED)
                                 .format(a=username, b=other, region=region, weather=weather))
            elif count == 5:
                bond_lore.append(_rng(f'bond:{key}:{count}').choice(_BOND_DEEPENED)
                                 .format(a=username, b=other, region=region, weather=weather))

        # Prophecy — soul-type aware
        prophecy_lore = []
        if r.random() < 0.08:
            if soul_type == 'seraph':
                pool = _PROPHECY_SERAPH
            elif soul_type == 'daemon':
                pool = _PROPHECY_DAEMON
            else:
                pool = _PROPHECY
            prophecy_lore.append(_rng(f'proph:{username}:{len(self.events)}').choice(pool)
                                 .format(user=username, region=region))

        self.save()

        stored = dict(self.users[username])
        stored['sigil_svg'] = generate_sigil_svg(username, size=40)
        return stored, lore, bond_lore, prophecy_lore

    def record_departure(self, username: str) -> list:
        region  = self._region_for(username)
        weather = self._weather(f'dw:{username}:{len(self.events)}')
        soul    = self._soul(username)
        r       = _rng(f'dep:{username}:{len(self.events)}')

        if soul == 'seraph':
            tpl = r.choice(_SERAPH_DEPARTURE)
        elif soul == 'daemon':
            tpl = r.choice(_DAEMON_DEPARTURE)
        else:
            tpl = r.choice(_DEPARTURE)

        lore = [l.format(user=username, region=region, weather=weather) for l in tpl]
        self.events.append({'text': lore[0], 'extra': lore[1:], 'user': username,
                            'type': 'departure', 'soul_type': soul, 'timestamp': time.time()})
        self.users[username]['last_seen'] = time.time()
        self.save()
        return lore

    def record_silence(self) -> list:
        lines = _rng(f'sil:{len(self.events)}').choice(_SILENCE)
        self.events.append({'text': lines[0], 'extra': lines[1:], 'type': 'silence', 'timestamp': time.time()})
        self.save()
        return lines

    def record_gathering(self, online_count: int, online_users: list = None) -> list:
        """Regular gathering (3-4 users)."""
        lines = _rng(f'gath:{len(self.events)}').choice(_GATHERING)
        self.events.append({'text': lines[0], 'extra': lines[1:], 'type': 'gathering', 'timestamp': time.time()})
        self.save()
        return lines

    def record_choir(self, online_count: int) -> list:
        """Liturgical choir event (5+ users)."""
        self.choir_count += 1
        nth    = _ordinal(self.choir_count)
        region = _rng(f'choir_region:{self.choir_count}').choice(
            [self._region_for(u) for u in self.users] or ['the Unknown Reaches']
        )
        r     = _rng(f'choir:{self.choir_count}')
        tpl   = r.choice(_CHOIR)
        lines = [l.format(count=online_count, nth=nth, region=region) for l in tpl]
        self.events.append({'text': lines[0], 'extra': lines[1:], 'type': 'choir',
                            'choir_count': self.choir_count, 'timestamp': time.time()})
        self.save()
        return lines

    def get_recent_lore(self, n: int = 5) -> list:
        out = []
        for e in self.events[-n:]:
            out.append(e['text'])
            out.extend(e.get('extra', []))
        return out

    def get_ghost_tales(self, n: int = 2) -> list:
        """Return up to n ghost tales from long-absent users."""
        tales = self._ghost_tales()
        if not tales: return []
        r = _rng(f'ghost_pick:{int(time.time() // 3600)}')  # refresh hourly
        r.shuffle(tales)
        return tales[:n]

    def get_prophecies(self) -> list:
        """Return all prophecy events from the record."""
        return [{'text': e['text'], 'user': e.get('user',''), 'timestamp': e.get('timestamp',0)}
                for e in self.events if e.get('type') == 'prophecy' or
                any(p in e.get('text','') for p in ['It is written','old records name','foretold','deep record'])]

    def get_all_bonds(self) -> list:
        """Return full bond list for the lore book."""
        out = []
        for key, bond in self.bonds.items():
            parts = key.split('|')
            if len(parts) == 2:
                out.append({'a': parts[0], 'b': parts[1],
                            'count': bond.get('count', 0),
                            'region': bond.get('region', ''),
                            'timestamp': bond.get('timestamp', 0)})
        return sorted(out, key=lambda x: x['count'], reverse=True)

    def get_all_users(self) -> list:
        """Return all user identity records for the lore book."""
        out = []
        for uname, udata in self.users.items():
            entry = dict(udata)
            entry['username'] = uname
            entry.pop('sigil_svg', None)
            out.append(entry)
        return sorted(out, key=lambda x: x.get('first_seen', 0))

    def get_world_summary(self) -> dict:
        season_name, _ = _season_info(self.created)
        soul_counts    = {}
        for u in self.users.values():
            s = u.get('soul_type', 'mortal')
            soul_counts[s] = soul_counts.get(s, 0) + 1
        return {
            'total_souls':   len(self.users),
            'total_events':  len(self.events),
            'total_bonds':   len(self.bonds),
            'choir_count':   self.choir_count,
            'recent_lore':   self.get_recent_lore(4),
            'ghost_tales':   self.get_ghost_tales(2),
            'world_age':     _world_age_str(self.created),
            'season':        season_name,
            'soul_counts':   soul_counts,
            'regions_known': list({self._region_for(u) for u in self.users}),
            'legend':        _rng(f'legend_pick:{int(time.time() // 7200)}').choice(
                                 list(self.legends.values())) if self.legends else None,
            'all_bonds':     self.get_all_bonds(),
            'all_users':     self.get_all_users(),
            'all_legends':   list(self.legends.values()),
            'all_ghosts':    self.get_ghost_tales(20),
            'full_events':   [{'text': e.get('text',''), 'extra': e.get('extra',[]),
                               'type': e.get('type',''), 'user': e.get('user',''),
                               'timestamp': e.get('timestamp', 0)}
                              for e in self.events[-100:]],
        }

    def get_user_identity(self, username: str) -> Optional[dict]:
        if username not in self.users: return None
        stored = dict(self.users[username])
        stored['sigil_svg'] = generate_sigil_svg(username, size=40)
        return stored
