# Templates

A **template** is a ready-made test for an app. You answer a few questions (where is the app in the backup,
which database version…), and the template writes the test for you.

In the template gallery you'll see three kinds:

| Badge | Meaning |
|---|---|
| **✓ verified** | tested against a real install of that app |
| **unverified** | written from the app's documentation, not yet tested against a real install. Run it once and check the result |
| **my template** | one you uploaded or saved yourself |

## Save your own test as a template

Made a test that works for one server and want it on another, or for a second copy of the app?

1. Open the application → **Save as my template**.
2. It appears in **Protect an application**, with a "my template" badge. It asks for a name and the app
   folder; everything else is copied from your test.

## Export and import

- **Export a template:** select it in the gallery → **Export template**. You get a `.json` file.
- **Upload a template:** **Upload template (.json)** in the gallery.
- **Export an application** (its test, ready to import elsewhere): application page → **Export (.json)**.
- **Import an application:** **Import an app (.json/.yaml)** in the gallery. It's created on the backup
  source selected at the top. If the name is taken, `-2` is added.

## Write a template by hand

A template is a JSON file. Here's a complete, working one:

```json
{
  "format": "restoreproof-template/v1",
  "id": "my-wiki",
  "name": "My wiki",
  "category": "Documents",
  "summary": "Pages folder plus the wiki's SQLite database.",
  "backup_guidance": ["Stop the wiki before the backup, or add a sqlite_backup hook."],
  "params": [
    {"key": "db_file", "label": "Database file", "default": "data/wiki.db"},
    {"key": "check_pages", "label": "Require the pages folder", "type": "bool", "default": true}
  ],
  "definition": {
    "spec": {
      "checks": [
        {"type": "sqlite_integrity", "path": "{{db_file}}", "tables": ["pages"]},
        {"$if": "check_pages", "type": "dir_not_empty", "path": "pages"}
      ]
    }
  }
}
```

### The parts

- **`id`**: lowercase letters, numbers and dashes. Uploading again with the same id replaces your old version.
- **`params`**: the questions shown in the form. Types: `string` (default), `int`, `bool`, `select`
  (with `"options": [...]`) and `list` (comma-separated input becomes a list).
- **`definition`**: the test, exactly as in [Writing a test](#/help/writing-tests), but as JSON. You can leave
  out `apiVersion`, `kind` and `metadata`; they are filled in.

### Placeholders

| Write | Becomes |
|---|---|
| `"{{db_file}}"` | the answer. When it's the whole value, the type is kept (a number stays a number, a list stays a list) |
| `"prefix-{{db_file}}"` | text with the answer inserted |
| `"{{dump_path\|gz}}"` | `gzip` if the answer ends in `.gz`, otherwise `none` (handy for `compression`) |
| `"{{app_dir\|prefix}}config.php"` | `config.php` if the answer is `.`, otherwise `app_dir/config.php` |

### Optional parts and lists

- `{"$if": "check_pages", ...}` inside a list keeps that item only when `check_pages` is on.
- `{"$if": "engine == mariadb", ...}` or `"engine != sqlite"` compares a select answer.
- `{"$for": "files", "$item": {"type": "file_exists", "path": "{{_}}"}}` makes one check per item of a list answer.

### Free questions you don't have to write

Every template automatically gets: **Test name**, **Path inside the snapshot** (the browse-and-pick
folder), **Maximum snapshot age**, **Snapshot host/tag filter**, **RPO target**, and **Detect shrinking
backups**. To switch these off, add `"standard_options": false` (name and path always stay).

## Checking your template

On upload, RestoreProof renders your template with its default answers and validates the result. If
something is wrong you get the exact field, for example `spec.checks.0.path: path traversal is not allowed`.

Library templates shipped with RestoreProof are written in this same format. Export one (for example
WordPress) to see a bigger real example.
