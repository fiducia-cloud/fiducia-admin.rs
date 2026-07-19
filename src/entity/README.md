# entity

SeaORM entity definitions for the admin plane's business tables. Same rule as
every fiducia service: Postgres holds business/control-plane rows only —
coordination state stays in the data plane's Raft groups.
