# Erebus Pro

Licensed extensions for the Erebus gateway. Source is public under the
[Elastic License 2.0](LICENSE); running Pro features needs a license key.

- Install next to Erebus: `pip install '.[gateway]' ./pro` (the published image already includes it).
- Configure: set `EREBUS_LICENSE_KEY=<key>` or `EREBUS_LICENSE_FILE=/path/to/key`.
- Check: `GET /v1/license` returns `status` (`none`, `valid`, `grace`, `expired`, `invalid`), `features`, `expires_at`.

A missing, expired or invalid key never stops the gateway. Pro features switch off; core filtering keeps running.
