CREATE TEMP TABLE _assert(ok INTEGER NOT NULL CHECK(ok = 1));

INSERT INTO _assert SELECT COUNT(*) = 2
FROM pragma_table_info('v2_uploads')
WHERE name IN ('snapshot_id','manifest_replay_id') AND type = 'BLOB' AND "notnull" = 1;
INSERT INTO _assert SELECT COUNT(*) = 1
FROM pragma_table_info('v2_uploads')
WHERE name = 'fleet_id' AND "notnull" = 1;

INSERT INTO _assert SELECT COUNT(*) = 3
FROM pragma_table_info('v2_snapshots')
WHERE name IN ('upload_id','snapshot_id','manifest_replay_id') AND "notnull" = 1;
INSERT INTO _assert SELECT COUNT(*) = 1
FROM pragma_table_info('v2_snapshots')
WHERE name = 'fleet_id' AND "notnull" = 1;

INSERT INTO _assert SELECT COUNT(*) = 1
FROM pragma_table_info('v2_root_key_generations')
WHERE name = 'server_instance_id' AND "notnull" = 1;
INSERT INTO _assert SELECT COUNT(*) = 1
FROM pragma_table_info('v2_fleet_key_generations')
WHERE name = 'server_instance_id' AND "notnull" = 1;

INSERT INTO _assert
SELECT EXISTS (
  SELECT 1
  FROM pragma_index_list('v2_fleet_key_generations') AS il
  JOIN pragma_index_info(il.name) AS ii
  WHERE il."unique" = 1
  GROUP BY il.name
  HAVING COUNT(*) = 5 AND
    MAX(ii.seqno = 0 AND ii.name = 'server_instance_id') = 1 AND
    MAX(ii.seqno = 1 AND ii.name = 'tenant_id') = 1 AND
    MAX(ii.seqno = 2 AND ii.name = 'fleet_id') = 1 AND
    MAX(ii.seqno = 3 AND ii.name = 'generation') = 1 AND
    MAX(ii.seqno = 4 AND ii.name = 'fkek_key_id') = 1
);

-- Exact five-column generation FK; run once per listed child table.
INSERT INTO _assert
SELECT EXISTS (
  SELECT 1 FROM pragma_foreign_key_list('v2_fleet_device_hpke_grants')
  WHERE "table" = 'v2_fleet_key_generations'
  GROUP BY id HAVING COUNT(*) = 5 AND
    MAX(seq = 0 AND "from" = 'server_instance_id' AND "to" = 'server_instance_id') = 1 AND
    MAX(seq = 1 AND "from" = 'tenant_id' AND "to" = 'tenant_id') = 1 AND
    MAX(seq = 2 AND "from" = 'fleet_id' AND "to" = 'fleet_id') = 1 AND
    MAX(seq = 3 AND "from" = 'generation' AND "to" = 'generation') = 1 AND
    MAX(seq = 4 AND "from" = 'fkek_key_id' AND "to" = 'fkek_key_id') = 1
);
INSERT INTO _assert
SELECT EXISTS (
  SELECT 1 FROM pragma_foreign_key_list('v2_fleet_recovery_grants')
  WHERE "table" = 'v2_fleet_key_generations'
  GROUP BY id HAVING COUNT(*) = 5 AND
    MAX(seq = 0 AND "from" = 'server_instance_id' AND "to" = 'server_instance_id') = 1 AND
    MAX(seq = 1 AND "from" = 'tenant_id' AND "to" = 'tenant_id') = 1 AND
    MAX(seq = 2 AND "from" = 'fleet_id' AND "to" = 'fleet_id') = 1 AND
    MAX(seq = 3 AND "from" = 'generation' AND "to" = 'generation') = 1 AND
    MAX(seq = 4 AND "from" = 'fkek_key_id' AND "to" = 'fkek_key_id') = 1
);
INSERT INTO _assert
SELECT EXISTS (
  SELECT 1 FROM pragma_foreign_key_list('v2_fleet_rotation_grants')
  WHERE "table" = 'v2_fleet_key_generations'
  GROUP BY id HAVING COUNT(*) = 5 AND
    MAX(seq = 0 AND "from" = 'server_instance_id' AND "to" = 'server_instance_id') = 1 AND
    MAX(seq = 1 AND "from" = 'tenant_id' AND "to" = 'tenant_id') = 1 AND
    MAX(seq = 2 AND "from" = 'fleet_id' AND "to" = 'fleet_id') = 1 AND
    MAX(seq = 3 AND "from" = 'generation' AND "to" = 'generation') = 1 AND
    MAX(seq = 4 AND "from" = 'fkek_key_id' AND "to" = 'fkek_key_id') = 1
);

-- Upload/snapshot use key_generation -> generation; both must carry fleet_id.
INSERT INTO _assert
SELECT EXISTS (
  SELECT 1 FROM pragma_foreign_key_list('v2_uploads')
  WHERE "table" = 'v2_fleet_key_generations'
  GROUP BY id HAVING COUNT(*) = 5 AND
    MAX(seq = 0 AND "from" = 'server_instance_id' AND "to" = 'server_instance_id') = 1 AND
    MAX(seq = 1 AND "from" = 'tenant_id' AND "to" = 'tenant_id') = 1 AND
    MAX(seq = 2 AND "from" = 'fleet_id' AND "to" = 'fleet_id') = 1 AND
    MAX(seq = 3 AND "from" = 'key_generation' AND "to" = 'generation') = 1 AND
    MAX(seq = 4 AND "from" = 'fkek_key_id' AND "to" = 'fkek_key_id') = 1
);
INSERT INTO _assert
SELECT EXISTS (
  SELECT 1 FROM pragma_foreign_key_list('v2_snapshots')
  WHERE "table" = 'v2_fleet_key_generations'
  GROUP BY id HAVING COUNT(*) = 5 AND
    MAX(seq = 0 AND "from" = 'server_instance_id' AND "to" = 'server_instance_id') = 1 AND
    MAX(seq = 1 AND "from" = 'tenant_id' AND "to" = 'tenant_id') = 1 AND
    MAX(seq = 2 AND "from" = 'fleet_id' AND "to" = 'fleet_id') = 1 AND
    MAX(seq = 3 AND "from" = 'key_generation' AND "to" = 'generation') = 1 AND
    MAX(seq = 4 AND "from" = 'fkek_key_id' AND "to" = 'fkek_key_id') = 1
);

INSERT INTO _assert
SELECT EXISTS (
  SELECT 1 FROM pragma_foreign_key_list('v2_snapshots')
  WHERE "table" = 'v2_uploads'
  GROUP BY id HAVING COUNT(*) = 6 AND
    MAX(seq = 0 AND "from" = 'server_instance_id' AND "to" = 'server_instance_id') = 1 AND
    MAX(seq = 1 AND "from" = 'tenant_id' AND "to" = 'tenant_id') = 1 AND
    MAX(seq = 2 AND "from" = 'upload_id' AND "to" = 'upload_id') = 1 AND
    MAX(seq = 3 AND "from" = 'fleet_id' AND "to" = 'fleet_id') = 1 AND
    MAX(seq = 4 AND "from" = 'snapshot_id' AND "to" = 'snapshot_id') = 1 AND
    MAX(seq = 5 AND "from" = 'manifest_replay_id' AND "to" = 'manifest_replay_id') = 1
);

PRAGMA integrity_check;
PRAGMA foreign_key_check;
