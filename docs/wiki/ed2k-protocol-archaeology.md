# eD2k Protocol Archaeology (historical study materials)

Updated: 2026-07-20

Reference/archaeology sources Anthony supplied 2026-07-20 - historical documents
and MetaMachine binaries that (a) independently CROSS-CONFIRM padMule's wire and
(b) are leads for the future [[future-lugdunum-modernization]] project. These are
DISTINCT from the code oracles in [[ref-source-trees]] (eMule 0.50a etc.): those
are the live authority; these are the original-era paper trail.

COPYRIGHT: the PDF is "Copyright SANS Institute, reposting not permitted"; the
eDonkey2000 binaries are proprietary MetaMachine. So NEITHER is vendored into this
PUBLIC repo - only the protocol FACTS (not copyrightable) are summarized here, with
attribution. Raw files live in Anthony's `C:\Users\ajbuf\Downloads\`, not git.

## The sources

1. **Gosling, Ian G. "eDonkey/ed2k: Study of A Young File Sharing Protocol"**
   (GIAC/SANS GCIH practical, 16 May 2003; `eDonkey-ed2k_study.pdf`, 46pp). A
   reverse-engineered study of the ORIGINAL MetaMachine eDonkey2000 protocol,
   pre-eMule-dominance - sniffed a live client/server and tabulated the wire.
2. **zed9h gist `dtool.pl`** (<https://gist.github.com/zed9h/149630>) - an
   mlDonkey-era Perl protocol tool with opcode/tag constants.
3. **oldversion.com/software/edonkey2000** - an archive of 17 MetaMachine
   BINARIES (client 0.44 -> 35.16.60), notably **Server 16.36 and Server 16.38**
   (Lugdunum dserver). Binaries only, no source.
4. **`edonkey-2000-gui-1.4.6.exe`** - the MetaMachine GUI client 1.4.6 installer.
   It is an NSIS 2.12 wrapper; the real binary is compressed inside (strings on
   the wrapper reveal only NSIS). Deeper extraction = a future archaeology task.
5. edonkey-plug-in-pack.software.informer.com - a plug-in-pack aggregator; the
   page 403s and is low value. Noted for completeness.

## Archaeological highlight (for [[future-lugdunum-modernization]])

The 2003 GIAC experiment (Section 7.2) sniffed a **Lugdunum "dserver" version
16.38.p72** in the wild (server ASCII in the dump: "server version 16.38.p72 ...
(lugdunum) ... This is the Dell server ... Check www.edonkey2000.com for
updates"). This is the SAME server family padMule tests against today
([[ed2k-server-oracle]] runs Lugdunum eserver 17.15) - so we now have a 2003
snapshot (16.38) and a 2007 binary (17.15) bracketing Lugdunum's evolution. The
16.36/16.38 server binaries are downloadable from oldversion.com (lead, not yet
pulled). Run any such binary ONLY isolated (`unshare -rn`), per the eserver rule.

## Wire cross-confirmations (differential value for padMule)

Everything below independently matches what padMule already implements - a free
outside-source check that our wire reading is right (not just self-consistent):

- Framing: `0xE3` eDonkey magic, then a 32-bit LE length, then a 1-byte type;
  "junk zeroes" sometimes trail a packet (poor original coding) - padMule already
  tolerates trailing bytes. server.met magic `0xE0` (dtool.pl).
- Ports: server tcp 4661 / udp 4665, client tcp 4662 / udp 4666, i.e. **udp =
  tcp + 4** - the padMule landmine ([[padmule-protocol-landmines]]).
- Server status ping: request `0xE3 96 95 02`, reply `0xE3 97 95 02`
  (OP_GLOBSERVSTATREQ 0x96 / OP_GLOBSERVSTATRES 0x97). NOTE: even the 2003 form
  carried a small echo token (`95 02`); modern eMule/aMule WIDENED it to the
  4-byte challenge padMule now sends + verifies (build-progress row 8x). Nice
  corroboration of that fix.
- Server-link opcodes: 0x01 login, 0x40 IDCHANGE (assigned id / "confirm client
  IP"), 0x34 SERVERSTATUS (users + files), 0x38 SERVERMESSAGE, 0x32 SERVERLIST,
  0x41 SERVERIDENT (name+title), 0x15 OFFERFILES, 0x4c connect-ack. All match.
- Global/extended search: `0xE3 0x98` (dtool.pl) = OP_GLOBSEARCHREQ (padMule #9).
- Peer opcodes: 0x58 request-filename, 0x59 filename-answer, 0x55 end-filename,
  0x47 request-parts, 0x46 sending-part, 0x57 end-of-data, 0x49 request-next,
  0x56 end-request, 0x54 ack. Match padMule's transfer path.
- Tags: two formats "tag1"/"tag2" (evidence the original had two authors) - the
  same split padMule's MET codec handles. Tag IDs: 0x01 name, 0x02 size, 0x03
  type, 0x08 transferred, 0x09/0x0A gap start/end, 0x0B description, 0x0E
  priority, 0x0F port, 0x11 version, 0x15 availability (dtool.pl) - our FT_* set.
- Hashing: MD4 over **9,728,000-byte** chunks (dtool.pl) - the eD2k PARTSIZE
  padMule uses.
- ed2k links: `ed2k://|file|<name>|<size>|<hash>|/` and
  `ed2k://|server|<ip>|<port>|/` - padMule's link parser.

One HISTORICAL divergence worth knowing: the 2003 "info on client storing the
file" (server->client) carried ONLY the storing peer's IP (no port); modern
source records carry IP+port. A reminder that the original wire was thinner than
today's - relevant when reading very old captures, not current interop.

## Related

- [[ref-source-trees]]
- [[protocol-reference]]
- [[ed2k-server-oracle]]
- [[padmule-protocol-landmines]]
- [[future-lugdunum-modernization]]
