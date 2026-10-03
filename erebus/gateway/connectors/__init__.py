"""Connector state in the gateway database (spec 015): sources, field mapping, sync jobs.

Store and policy only. Nothing here contacts a source system or loads a connector
driver; the sync worker does that (D1).
"""
