-- v1.1 hardening: enforce the device invariants in the schema, not only in code, so a
-- bug or a concurrent writer can never leave two rows for one peer or two self rows.
--
-- Reconcile any historical rows FIRST, so this migration also succeeds on a database that
-- predates these constraints (older builds lacked the transactional upsert guards and could
-- race two self rows or a duplicated peer into existence).

-- 1. Normalize is_self to strict 0/1. The code reads any nonzero value as "self"
--    (device_from_row uses != 0) while this index and the self-device queries use = 1;
--    collapse a legacy value like 2 to 1 so the two agree and it cannot slip past the index.
UPDATE devices SET is_self = 1 WHERE is_self <> 0;

-- 2. Collapse multiple self rows to one deterministic survivor (the lowest rowid); demote
--    the rest to peers rather than deleting them, so no device is lost outright.
UPDATE devices SET is_self = 0
 WHERE is_self = 1
   AND rowid <> (SELECT MIN(rowid) FROM devices WHERE is_self = 1);

-- 3. Deduplicate public_key: keep the lowest rowid per key and delete the rest. The key IS
--    the device identity on the wire, so a duplicate is a true redundancy, not a distinct
--    device.
DELETE FROM devices
 WHERE rowid NOT IN (SELECT MIN(rowid) FROM devices GROUP BY public_key);

-- One row per peer public key. Duplicates would make find_device_by_public_key ambiguous
-- and let a peer be paired twice.
CREATE UNIQUE INDEX idx_devices_public_key ON devices(public_key);

-- At most one self row. A partial index over the always-1 value enforces "single is_self".
CREATE UNIQUE INDEX idx_devices_single_self ON devices(is_self) WHERE is_self = 1;
