# ai-ir2: AI駆動インシデントレスポンス分析

[English](README.md)

`ai-ir2` は [scat](https://github.com/nlink-jp/scat)、[stail](https://github.com/nlink-jp/stail)、
または [scli](https://github.com/nlink-jp/scli) でエクスポートしたインシデントレスポンス Slack 会話履歴を
単一コマンドで包括的に分析するツールです。

**Vertex AI Gemini** を使用し、Application Default Credentials で認証します。

## 機能

- **ワンストップ分析** — `aiir2 analyze` 一発でインジェスト、サマリ、行動分析、役割推定、プロセスレビュー、タクティクス抽出を実行
- **マルチフォーマット出力** — Markdown レポート、自己完結 HTML（単一ファイルで共有可能）、YAML/Markdown ナレッジドキュメント
- **組み込み翻訳** — `--lang ja` を指定するだけで翻訳版も同時出力（英語版は常に生成）
- **セキュリティファースト** — IoC 無害化、nonce タグによるプロンプト注入防御
- **Vertex AI Gemini** — `response_schema` による構造化出力、ADC 認証

## 前提条件

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) パッケージマネージャー
- Vertex AI API が有効な GCP プロジェクト
- Application Default Credentials: `gcloud auth application-default login`

## インストール

```bash
uv sync
```

## クイックスタート

```bash
# Slack チャンネル履歴をエクスポート
stail export -c "#incident-response" --output incident.json

# 全分析を実行（英語＋日本語）
aiir2 analyze incident.json --lang ja

# 出力ディレクトリ構造:
# {incident_id}/
# ├── en/report.md, report.html
# ├── ja/report.md, report.html
# ├── knowledge/*.yaml, *.md
# └── preprocessed.json
```

## 設定

### 設定ファイル

`ai-ir2` は `~/.config/ai-ir2/config.toml` の TOML 設定ファイルをサポートしています。

```bash
# セットアップ
mkdir -p ~/.config/ai-ir2
cp config.example.toml ~/.config/ai-ir2/config.toml
# 設定を編集
```

### 優先順位

設定は以下の優先順位で解決されます（上位が優先）:

1. CLI フラグ (`--project`, `--location`, `--model`, `--timezone`)
2. 環境変数 (`AIIR2_PROJECT` など)
3. `.env` ファイル
4. 設定ファイル (`~/.config/ai-ir2/config.toml`)
5. デフォルト値

### 環境変数

| 環境変数 | デフォルト | 説明 |
|---------|-----------|------|
| `AIIR2_PROJECT` | （必須） | GCP プロジェクト ID |
| `AIIR2_LOCATION` | `us-central1` | Vertex AI ロケーション |
| `AIIR2_MODEL` | `gemini-2.5-flash` | Gemini モデル名 |
| `AIIR2_TIMEZONE` | `UTC` | レポートのタイムスタンプに使用するタイムゾーン（IANA 名、例: `Asia/Tokyo`） |

## コマンド

```bash
aiir2 analyze <input.json>          # 全分析パイプライン
aiir2 analyze <input.json> --lang ja --lang zh  # 翻訳付き
aiir2 analyze <input.json> -o ./out  # カスタム出力ディレクトリ
aiir2 analyze <input.json> --timezone Asia/Tokyo  # タイムスタンプのタイムゾーン指定
aiir2 config show                    # 現在の設定を表示
```

## ドキュメント

- [Analysis Methodology](docs/en/analysis-methodology.md) / [分析手法](docs/ja/analysis-methodology.md)
- [Data Format](docs/en/data-format.md) / [データフォーマット](docs/ja/data-format.md)

## ライセンス

MIT
