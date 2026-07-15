ALTER TABLE projects ADD COLUMN local_path TEXT;

CREATE UNIQUE INDEX projects_local_path_unique ON projects(local_path);
