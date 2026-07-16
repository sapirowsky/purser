-- v1.1 hardening: enforce the device invariants in the schema, not only in code, so a
-- bug or a concurrent writer can never leave two rows for one peer or two self rows.

-- One row per peer public key. The key IS the device identity on the wire; duplicates
-- would make find_device_by_public_key ambiguous and let a peer be paired twice.
CREATE UNIQUE INDEX idx_devices_public_key ON devices(public_key);

-- At most one self row. A partial index over the always-1 value enforces "single is_self".
CREATE UNIQUE INDEX idx_devices_single_self ON devices(is_self) WHERE is_self = 1;
