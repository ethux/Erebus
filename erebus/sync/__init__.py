"""The sync worker (spec 015 D1): ``erebus-sync``.

The only process that contacts source systems. It claims ``sync_jobs`` from the gateway
database, opens a source with its connector, maps fields (sample jobs) and upserts and
retires known values (full syncs). It needs the gateway's DSN and master key, not the
gateway's provider settings, and serves no traffic.
"""
