# Upstream aMule 3.0.1 - Layout, Build, Port Seams

Updated: 2026-07-18

Source: `amule-3.0.1/` at the repo root (extracted from the pristine zip at
`/mnt/c/Users/ajbuf/Downloads/amule-3.0.1.zip`). GPL-2.0-or-later. Role today:
vendored read-only REFERENCE ORACLE for differential testing (the engine is a
Rust rewrite - [[decisions-and-lessons]]); never linked or shipped.

## Layout

- `src/` - engine and wxWidgets GUI in ONE flat tree (~446 .cpp/.h). Engine:
  `BaseClient`, `ClientTCPSocket`/`ClientUDPSocket`, `DownloadQueue`/
  `UploadQueue`, part/known file handling, `ClientList`/server lists,
  `ClientCredits`. GUI: dialogs/windows interleaved in the same directory
  (ChatWnd, CatDialog, ClientDetailDialog, ...).
- `src/kademlia/` - Kad DHT, subdirs kademlia / net / routing / utils.
- `src/libs/common` - shared utility lib.
- `src/libs/ec` - External Connections (EC) protocol: remote control of a
  running engine; abstracts + cpp + java bindings; codegen via file_generator.pl.
- `unittests/` - upstream tests, CMake `BUILD_TESTING`.
- `platforms/MacOSX` - only Apple glue upstream ships (desktop macOS).

## Build

CMake. Options: `BUILD_MONOLITHIC` (GUI app, ON), `BUILD_DAEMON` (amuled,
headless), `BUILD_REMOTEGUI` (amulegui over EC), `BUILD_AMULECMD`,
`BUILD_WEBSERVER`, `BUILD_TESTING`, plus `ENABLE_UPNP`/`ENABLE_IP2COUNTRY`/
`ENABLE_NLS` etc. Deps: wxWidgets, Crypto++, zlib, optional UPnP/GeoIP.

## Port-relevant facts

- wxWidgets types (wxString, threads, events) pervade the ENGINE, not just the
  GUI - de-wx-ing the core is real work regardless of UI strategy.
- amuled + EC is the natural seam UPSTREAM: headless engine below EC, any UI
  above it (how amulegui/amuleweb/amulecmd work). [SUPERSEDED for padMule: the
  decided seam is the in-process UniFFI FFI (`crates/mule-ffi`); EC was
  deferred entirely - [[build-progress]] wave 7.]
- Official docs confirm the modular amule/amuled/amulegui/amuleweb/amulecmd
  architecture and ARM64 support on desktop platforms ([[ref-ecosystem]]).

## Related

- [[ref-ecosystem]]
