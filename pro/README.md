# Erebus Pro

Licensed extensions for the Erebus gateway. Source is public under the
[Elastic License 2.0](LICENSE); running Pro features needs a license key.

- Install next to Erebus: `pip install '.[gateway]' ./pro` (the published image already includes it).
- Configure: set `EREBUS_LICENSE_KEY=<key>` or `EREBUS_LICENSE_FILE=/path/to/key`.
- Check: `GET /v1/license` returns `status` (`none`, `valid`, `grace`, `expired`, `invalid`), `features`, `expires_at`.

Features this package gates:

- `sync.schedule`: scheduled syncs of connected sources, run by the sync worker, and
  `PUT /v1/admin/scopes/{scope_id}/sources/{source_id}/schedule`. Set the key for the gateway
  and the sync worker.

A missing, expired or invalid key never stops the gateway. Pro features switch off; core filtering keeps running.
