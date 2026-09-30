"""Free source connectors (spec 015 "Architecture": contract additions).

Each module imports its driver inside ``connect()`` and registers through the
``erebus.sources`` entry-point group (SQLite is the laptop's built-in and is registered
lazily by ``erebus.cataloging.sources``). Only the sync worker and the laptop editor load
these; the gateway process never does (SC-5). Every driver failure leaves as a fixed-text
``ConnectorError`` raised ``from None``.
"""
