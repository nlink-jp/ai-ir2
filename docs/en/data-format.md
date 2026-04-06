# Data Format

## Input Format

ai-ir2 accepts Slack conversation exports produced by [scat](https://github.com/nlink-jp/scat), [stail](https://github.com/nlink-jp/stail), or [scli](https://github.com/nlink-jp/scli).

Two formats are supported:

### Single JSON (scat format)

A single JSON object containing the full export:

```json
{
  "export_timestamp": "2026-03-19T10:30:00+09:00",
  "channel_name": "incident-response",
  "messages": [
    {
      "user_id": "U12345678",
      "user_name": "alice",
      "post_type": "user",
      "timestamp": "2026-03-19T09:00:00+09:00",
      "timestamp_unix": "1742342400.000000",
      "text": "We're seeing elevated error rates on the API gateway.",
      "files": [],
      "attachments": [],
      "blocks": [],
      "thread_timestamp_unix": "",
      "is_reply": false
    }
  ]
}
```

### NDJSON (stail format)

One `SlackMessage` JSON object per line. The channel name is derived from the file stem, and the export timestamp from the latest message:

```
{"user_id":"U12345678","user_name":"alice","post_type":"user","timestamp":"2026-03-19T09:00:00+09:00","timestamp_unix":"1742342400.000000","text":"Investigating the issue.","files":[],"attachments":[],"blocks":[],"thread_timestamp_unix":"","is_reply":false}
{"user_id":"U87654321","user_name":"bob","post_type":"user","timestamp":"2026-03-19T09:05:00+09:00","timestamp_unix":"1742342700.000000","text":"Found the root cause.","files":[],"attachments":[],"blocks":[],"thread_timestamp_unix":"","is_reply":false}
```

### Message Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `user_id` | string | yes | Slack user ID |
| `user_name` | string | no | Display name (falls back to `user_id` if empty) |
| `post_type` | string | yes | `"user"` or `"bot"` |
| `timestamp` | string | yes | ISO 8601 datetime with timezone |
| `timestamp_unix` | string | yes | Unix timestamp as string (e.g., `"1742342400.000000"`) |
| `text` | string | yes | Message text content |
| `files` | array | no | Attached file metadata |
| `attachments` | array | no | Legacy rich attachments (see below) |
| `blocks` | array | no | Block Kit layout blocks (see below) |
| `thread_timestamp_unix` | string | no | Parent thread timestamp (empty for top-level messages) |
| `is_reply` | boolean | no | Whether this message is a thread reply |

### Attachments

Legacy Slack attachments provide rich formatting for bot messages, integrations, and unfurled links. When a message's `text` field is empty, ai-ir2 reconstructs the text content from attachment fields.

| Field | Type | Description |
|-------|------|-------------|
| `fallback` | string | Plain-text summary (used as last resort for text extraction) |
| `color` | string | Sidebar color hex code |
| `pretext` | string | Text displayed above the attachment body |
| `title` | string | Bold title text |
| `title_link` | string | URL for the title |
| `text` | string | Main body text of the attachment |
| `fields` | array | Key-value field pairs |
| `footer` | string | Footer text |
| `image_url` | string | URL of an attached image |

Text extraction priority for empty-text messages: `pretext` > `title` > `text` > `fallback`.

### Blocks

Block Kit blocks provide modern structured message layouts. When a message's `text` field is empty and no attachment text is available, ai-ir2 recursively extracts plain text from block elements.

Supported block structures:
- Section and header blocks with a `text` object
- Rich-text blocks with nested `elements` arrays (up to 3 levels deep)

Text is extracted by traversing the `text` field of each element and its children.

## Export Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `export_timestamp` | string | yes | ISO 8601 datetime when the export was created |
| `channel_name` | string | yes | Slack channel name (without `#`) |
| `messages` | array | yes | Array of SlackMessage objects |
