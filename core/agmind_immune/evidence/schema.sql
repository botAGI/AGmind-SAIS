CREATE TABLE schema_meta (
    key TEXT COLLATE BINARY PRIMARY KEY,
    value TEXT COLLATE BINARY NOT NULL
) WITHOUT ROWID;

INSERT INTO schema_meta(key, value) VALUES
    ('schema_version', 'agmind.projection-schema.v1'),
    ('reducer_version', 'agmind.projection-reducer.v1'),
    ('snapshot_layout', 'AGMIND_PROJECTION_SNAPSHOT_V1');

CREATE TABLE events (
    event_id TEXT COLLATE BINARY PRIMARY KEY,
    host_id TEXT COLLATE BINARY NOT NULL,
    source_sequence TEXT COLLATE BINARY NOT NULL
        CHECK(length(source_sequence)=20 AND source_sequence NOT GLOB '*[^0-9]*'),
    event_type TEXT COLLATE BINARY NOT NULL,
    source_id TEXT COLLATE BINARY NOT NULL,
    source_version TEXT COLLATE BINARY NOT NULL,
    key_id TEXT COLLATE BINARY NOT NULL,
    key_epoch TEXT COLLATE BINARY NOT NULL
        CHECK(length(key_epoch)=20 AND key_epoch NOT GLOB '*[^0-9]*'),
    boot_id TEXT COLLATE BINARY NOT NULL,
    event_time TEXT COLLATE BINARY NOT NULL,
    ingest_time TEXT COLLATE BINARY NOT NULL,
    clock_uncertainty_ms INTEGER NOT NULL CHECK(clock_uncertainty_ms BETWEEN 0 AND 2000),
    container_id TEXT COLLATE BINARY,
    container_start_time TEXT COLLATE BINARY,
    release_id TEXT COLLATE BINARY,
    inventory_generation TEXT COLLATE BINARY NOT NULL
        CHECK(length(inventory_generation)=20 AND inventory_generation NOT GLOB '*[^0-9]*'),
    inventory_revision TEXT COLLATE BINARY
        CHECK(inventory_revision IS NULL OR
              (length(inventory_revision)=20 AND inventory_revision NOT GLOB '*[^0-9]*')),
    normalized_fields_json TEXT COLLATE BINARY NOT NULL,
    normalized_fields_sha256 TEXT COLLATE BINARY NOT NULL,
    redaction_flags_json TEXT COLLATE BINARY NOT NULL,
    coverage_flags_json TEXT COLLATE BINARY NOT NULL,
    source_payload_hash TEXT COLLATE BINARY NOT NULL,
    source_signature TEXT COLLATE BINARY NOT NULL,
    segment_id TEXT COLLATE BINARY NOT NULL,
    segment_relative_path TEXT COLLATE BINARY NOT NULL,
    frame_offset TEXT COLLATE BINARY NOT NULL
        CHECK(length(frame_offset)=20 AND frame_offset NOT GLOB '*[^0-9]*'),
    frame_size TEXT COLLATE BINARY NOT NULL
        CHECK(length(frame_size)=20 AND frame_size NOT GLOB '*[^0-9]*'),
    frame_sha256 TEXT COLLATE BINARY NOT NULL,
    canonical_sha256 TEXT COLLATE BINARY NOT NULL,
    content_sha256 TEXT COLLATE BINARY NOT NULL,
    duplicate_of_event_id TEXT COLLATE BINARY,
    UNIQUE(host_id, source_sequence),
    UNIQUE(segment_id, segment_relative_path, frame_offset, frame_size, frame_sha256),
    FOREIGN KEY(duplicate_of_event_id) REFERENCES events(event_id)
) WITHOUT ROWID;

CREATE TABLE projection_dedup (
    event_id TEXT COLLATE BINARY PRIMARY KEY,
    dedup_kind TEXT COLLATE BINARY NOT NULL,
    logical_key_sha256 TEXT COLLATE BINARY NOT NULL,
    primary_event_id TEXT COLLATE BINARY NOT NULL,
    is_primary INTEGER NOT NULL CHECK(is_primary IN (0,1)),
    FOREIGN KEY(event_id) REFERENCES events(event_id),
    FOREIGN KEY(primary_event_id) REFERENCES events(event_id)
) WITHOUT ROWID;

CREATE UNIQUE INDEX projection_one_logical_primary
ON projection_dedup(dedup_kind, logical_key_sha256)
WHERE is_primary = 1;

CREATE TABLE coverage_intervals (
    event_id TEXT COLLATE BINARY PRIMARY KEY,
    host_id TEXT COLLATE BINARY NOT NULL,
    component TEXT COLLATE BINARY NOT NULL,
    kind TEXT COLLATE BINARY NOT NULL,
    severity TEXT COLLATE BINARY NOT NULL,
    opened_at TEXT COLLATE BINARY NOT NULL,
    closed_at TEXT COLLATE BINARY,
    affected_source_sequence_start TEXT COLLATE BINARY
        CHECK(affected_source_sequence_start IS NULL OR
              (length(affected_source_sequence_start)=20 AND
               affected_source_sequence_start NOT GLOB '*[^0-9]*')),
    affected_source_sequence_end TEXT COLLATE BINARY
        CHECK(affected_source_sequence_end IS NULL OR
              (length(affected_source_sequence_end)=20 AND
               affected_source_sequence_end NOT GLOB '*[^0-9]*')),
    dropped_count TEXT COLLATE BINARY
        CHECK(dropped_count IS NULL OR
              (length(dropped_count)=20 AND dropped_count NOT GLOB '*[^0-9]*')),
    reason_code TEXT COLLATE BINARY NOT NULL,
    reconcile_generation TEXT COLLATE BINARY
        CHECK(reconcile_generation IS NULL OR
              (length(reconcile_generation)=20 AND
               reconcile_generation NOT GLOB '*[^0-9]*')),
    source_sequence TEXT COLLATE BINARY NOT NULL
        CHECK(length(source_sequence)=20 AND source_sequence NOT GLOB '*[^0-9]*'),
    content_sha256 TEXT COLLATE BINARY NOT NULL,
    FOREIGN KEY(event_id) REFERENCES events(event_id)
) WITHOUT ROWID;

CREATE TABLE containers (
    host_id TEXT COLLATE BINARY NOT NULL,
    container_id TEXT COLLATE BINARY NOT NULL,
    container_started_at TEXT COLLATE BINARY NOT NULL,
    image_id TEXT COLLATE BINARY,
    repo_digests_json TEXT COLLATE BINARY NOT NULL,
    immutable_spec_sha256 TEXT COLLATE BINARY,
    inventory_revision TEXT COLLATE BINARY
        CHECK(inventory_revision IS NULL OR
              (length(inventory_revision)=20 AND inventory_revision NOT GLOB '*[^0-9]*')),
    first_event_id TEXT COLLATE BINARY NOT NULL,
    first_source_sequence TEXT COLLATE BINARY NOT NULL
        CHECK(length(first_source_sequence)=20 AND
              first_source_sequence NOT GLOB '*[^0-9]*'),
    first_content_sha256 TEXT COLLATE BINARY NOT NULL,
    last_event_id TEXT COLLATE BINARY NOT NULL,
    last_source_sequence TEXT COLLATE BINARY NOT NULL
        CHECK(length(last_source_sequence)=20 AND
              last_source_sequence NOT GLOB '*[^0-9]*'),
    last_content_sha256 TEXT COLLATE BINARY NOT NULL,
    PRIMARY KEY(host_id, container_id, container_started_at),
    FOREIGN KEY(first_event_id) REFERENCES events(event_id),
    FOREIGN KEY(last_event_id) REFERENCES events(event_id)
) WITHOUT ROWID;

CREATE TABLE process_observations (
    event_id TEXT COLLATE BINARY PRIMARY KEY,
    host_id TEXT COLLATE BINARY NOT NULL,
    container_id TEXT COLLATE BINARY,
    container_started_at TEXT COLLATE BINARY,
    proc_name TEXT COLLATE BINARY,
    proc_exe_path TEXT COLLATE BINARY,
    proc_parent_name TEXT COLLATE BINARY,
    source_sequence TEXT COLLATE BINARY NOT NULL
        CHECK(length(source_sequence)=20 AND source_sequence NOT GLOB '*[^0-9]*'),
    content_sha256 TEXT COLLATE BINARY NOT NULL,
    FOREIGN KEY(event_id) REFERENCES events(event_id)
) WITHOUT ROWID;

CREATE TABLE network_observations (
    event_id TEXT COLLATE BINARY PRIMARY KEY,
    host_id TEXT COLLATE BINARY NOT NULL,
    container_id TEXT COLLATE BINARY,
    container_started_at TEXT COLLATE BINARY,
    successful_connect INTEGER NOT NULL CHECK(successful_connect IN (0,1)),
    destination_ipv4 TEXT COLLATE BINARY,
    destination_port INTEGER CHECK(destination_port BETWEEN 1 AND 65535),
    l4_protocol TEXT COLLATE BINARY,
    investigation_only INTEGER NOT NULL CHECK(investigation_only IN (0,1)),
    source_sequence TEXT COLLATE BINARY NOT NULL
        CHECK(length(source_sequence)=20 AND source_sequence NOT GLOB '*[^0-9]*'),
    content_sha256 TEXT COLLATE BINARY NOT NULL,
    FOREIGN KEY(event_id) REFERENCES events(event_id)
) WITHOUT ROWID;

CREATE TABLE ingest_cursors (
    host_id TEXT COLLATE BINARY PRIMARY KEY,
    source_sequence TEXT COLLATE BINARY NOT NULL
        CHECK(length(source_sequence)=20 AND source_sequence NOT GLOB '*[^0-9]*'),
    event_id TEXT COLLATE BINARY NOT NULL,
    content_sha256 TEXT COLLATE BINARY NOT NULL,
    segment_id TEXT COLLATE BINARY NOT NULL,
    segment_relative_path TEXT COLLATE BINARY NOT NULL,
    frame_offset TEXT COLLATE BINARY NOT NULL
        CHECK(length(frame_offset)=20 AND frame_offset NOT GLOB '*[^0-9]*'),
    frame_size TEXT COLLATE BINARY NOT NULL
        CHECK(length(frame_size)=20 AND frame_size NOT GLOB '*[^0-9]*'),
    frame_sha256 TEXT COLLATE BINARY NOT NULL,
    FOREIGN KEY(event_id) REFERENCES events(event_id)
) WITHOUT ROWID;
