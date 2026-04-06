# データフォーマット

## 入力フォーマット

ai-ir2 は [scat](https://github.com/nlink-jp/scat)、[stail](https://github.com/nlink-jp/stail)、または [scli](https://github.com/nlink-jp/scli) で生成された Slack 会話エクスポートを受け付けます。

2つのフォーマットに対応しています：

### 単一 JSON（scat フォーマット）

エクスポート全体を含む単一の JSON オブジェクト：

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
      "text": "API ゲートウェイでエラー率が上昇しています。",
      "files": [],
      "attachments": [],
      "blocks": [],
      "thread_timestamp_unix": "",
      "is_reply": false
    }
  ]
}
```

### NDJSON（stail フォーマット）

1行に1つの `SlackMessage` JSON オブジェクト。チャンネル名はファイル名から、エクスポートタイムスタンプは最新のメッセージから導出されます：

```
{"user_id":"U12345678","user_name":"alice","post_type":"user","timestamp":"2026-03-19T09:00:00+09:00","timestamp_unix":"1742342400.000000","text":"問題を調査中です。","files":[],"attachments":[],"blocks":[],"thread_timestamp_unix":"","is_reply":false}
{"user_id":"U87654321","user_name":"bob","post_type":"user","timestamp":"2026-03-19T09:05:00+09:00","timestamp_unix":"1742342700.000000","text":"根本原因を発見しました。","files":[],"attachments":[],"blocks":[],"thread_timestamp_unix":"","is_reply":false}
```

### メッセージフィールド

| フィールド | 型 | 必須 | 説明 |
|-----------|------|------|------|
| `user_id` | string | はい | Slack ユーザー ID |
| `user_name` | string | いいえ | 表示名（空の場合は `user_id` にフォールバック） |
| `post_type` | string | はい | `"user"` または `"bot"` |
| `timestamp` | string | はい | タイムゾーン付き ISO 8601 日時 |
| `timestamp_unix` | string | はい | 文字列としての Unix タイムスタンプ（例: `"1742342400.000000"`） |
| `text` | string | はい | メッセージテキスト内容 |
| `files` | array | いいえ | 添付ファイルメタデータ |
| `attachments` | array | いいえ | レガシーリッチ添付（下記参照） |
| `blocks` | array | いいえ | Block Kit レイアウトブロック（下記参照） |
| `thread_timestamp_unix` | string | いいえ | 親スレッドのタイムスタンプ（トップレベルメッセージの場合は空） |
| `is_reply` | boolean | いいえ | スレッド返信かどうか |

### Attachments（添付）

レガシー Slack attachments はボットメッセージ、インテグレーション、展開されたリンクにリッチフォーマットを提供します。メッセージの `text` フィールドが空の場合、ai-ir2 は attachment フィールドからテキスト内容を再構成します。

| フィールド | 型 | 説明 |
|-----------|------|------|
| `fallback` | string | プレーンテキストサマリ（テキスト抽出の最終手段として使用） |
| `color` | string | サイドバーカラー16進コード |
| `pretext` | string | attachment 本文の上に表示されるテキスト |
| `title` | string | 太字のタイトルテキスト |
| `title_link` | string | タイトルの URL |
| `text` | string | attachment のメイン本文テキスト |
| `fields` | array | キーバリューフィールドペア |
| `footer` | string | フッターテキスト |
| `image_url` | string | 添付画像の URL |

空テキストメッセージのテキスト抽出優先順位: `pretext` > `title` > `text` > `fallback`。

### Blocks（ブロック）

Block Kit ブロックはモダンな構造化メッセージレイアウトを提供します。メッセージの `text` フィールドが空で attachment テキストも利用できない場合、ai-ir2 はブロック要素からプレーンテキストを再帰的に抽出します。

サポートされるブロック構造：
- `text` オブジェクトを持つ section および header ブロック
- ネストされた `elements` 配列を持つ rich-text ブロック（最大3レベルの深さ）

テキストは各要素とその子の `text` フィールドを走査して抽出されます。

## エクスポートフィールド

| フィールド | 型 | 必須 | 説明 |
|-----------|------|------|------|
| `export_timestamp` | string | はい | エクスポートが作成された ISO 8601 日時 |
| `channel_name` | string | はい | Slack チャンネル名（`#` なし） |
| `messages` | array | はい | SlackMessage オブジェクトの配列 |
