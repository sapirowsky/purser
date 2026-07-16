-- v1.1 device mesh: devices gossip the device list so any two paired devices learn about
-- every other paired device, without one machine having to be a hub.
--
-- `revoked` is a replicating tombstone for `purser device forget`: once set it spreads with
-- the gossip instead of being undone the next time the forgotten device syncs back in. It is
-- bookkeeping, not security on its own — a revoked device still holds the vault key it was
-- given. Reclaiming that needs key rotation (a separate, real ceremony).
ALTER TABLE devices ADD COLUMN revoked INTEGER NOT NULL DEFAULT 0;
