import os
import sys
import argparse
import json
import traceback
import pyodbc

# Try modern OpenAI SDK first; fallback to legacy if needed
try:
    from openai import OpenAI
    _OPENAI_SDK = "v1"
except Exception:
    import openai as OpenAI  # type: ignore
    _OPENAI_SDK = "legacy"


def build_conn_str(
    server=r"localhost\SQLEXPRESS",
    database="false_positive",
    driver="ODBC Driver 17 for SQL Server",
    trusted_connection="yes",
) -> str:
    # Construct a robust SQL Server connection string
    return (
        f"Driver={{{driver}}};"
        f"Server={server};"
        f"Database={database};"
        f"Trusted_Connection={trusted_connection};"
    )


def get_openai_client(api_key: str):
    if _OPENAI_SDK == "v1":
        return OpenAI(api_key=api_key)
    else:
        OpenAI.api_key = api_key  # legacy
        return OpenAI


def analyze_with_gpt(client, model: str, payload: dict):
    """
    Ask GPT-4o to classify the alert based on code_snippet, dismissed_reason,
    and dismissed_comment. Returns a dict with classification, reasoning, and recommended_action.
    """
    system_msg = (
        "You are a senior security analyst and software developer. "
        "Evaluate the provided alert and code snippet. "
        "Decide whether it is a false_positive, true_positive, or secure. "
        "Use the dismissed_reason and dismissed_comment as context. "
        "If evidence is insufficient, use 'uncertain'. "
        "Respond with ONLY a compact JSON object: "
        '{"classification":"false_positive|true_positive|secure|uncertain",'
        '"reasoning":"...",'
        '"recommended_action":"..."}'
    )

    user_msg = (
        "Analyze this alert and code snippet.\n"
        f"alert_id: {payload.get('alert_id')}\n"
        f"rule_id: {payload.get('rule_id')}\n"
        f"dismissed_reason: {payload.get('dismissed_reason')}\n"
        f"dismissed_comment: {payload.get('dismissed_comment')}\n"
        "code_snippet:\n"
        f"{payload.get('code_snippet')}\n"
    )

    try:
        if _OPENAI_SDK == "v1":
            resp = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system_msg},
                    {"role": "user", "content": user_msg},
                ],
                temperature=0.2,
                max_tokens=500,
            )
            content = resp.choices[0].message.content
        else:
            resp = client.ChatCompletion.create(
                model=model,
                messages=[
                    {"role": "system", "content": system_msg},
                    {"role": "user", "content": user_msg},
                ],
                temperature=0.2,
                max_tokens=500,
            )
            content = resp.choices[0].message["content"]

        # Parse JSON strictly; try to recover if wrapped
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            start = content.find("{")
            end = content.rfind("}")
            if start != -1 and end != -1 and end > start:
                return json.loads(content[start : end + 1])
            return {
                "classification": "uncertain",
                "reasoning": "Model returned non-JSON content.",
                "recommended_action": "Review manually.",
            }
    except Exception as api_err:
        return {
            "classification": "uncertain",
            "reasoning": f"API error: {api_err}",
            "recommended_action": "Retry or check API configuration.",
        }


def main():
    parser = argparse.ArgumentParser(
        description="Query SQL Server alerts, analyze code snippets with GPT-4o per row."
    )
    parser.add_argument(
        "-k", "--api-key", dest="api_key", default=os.getenv("OPENAI_API_KEY"),
        help="OpenAI API key (or set OPENAI_API_KEY env var)."
    )
    parser.add_argument(
        "--server", default=r"localhost\SQLEXPRESS",
        help="SQL Server instance (default: localhost\\SQLEXPRESS)."
    )
    parser.add_argument(
        "--database", default="false_positive",
        help="Database name (default: false_positive)."
    )
    parser.add_argument(
        "--driver", default="ODBC Driver 17 for SQL Server",
        help='ODBC driver (default: "ODBC Driver 17 for SQL Server").'
    )
    parser.add_argument(
        "--model", default="gpt-4o",
        help="OpenAI model to use (default: gpt-4o)."
    )
    parser.add_argument(
        "--db_timeout", type=int, default=30,
        help="Database connection timeout in seconds (default: 30)."
    )
    args = parser.parse_args()

    if not args.api_key:
        print("Error: OpenAI API key not provided. Use -k or set OPENAI_API_KEY.", file=sys.stderr)
        sys.exit(1)

    # Read the API key from the file specified by the -k argument
    try:
        with open(args.api_key, "r") as file:
            args.api_key = file.read().strip()
    except FileNotFoundError:
        print(f"Error: API key file not found: {args.api_key}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error reading API key file: {str(e)}", file=sys.stderr)
        sys.exit(1)

    conn = None
    cursor = None

    conn_str = build_conn_str(
        server=args.server,
        database=args.database,
        driver=args.driver,
        trusted_connection="yes",
    )

    try:
        # Connect to SQL Server
        conn = pyodbc.connect(conn_str, timeout=args.db_timeout)
        cursor = conn.cursor()

        # Only required columns; filter out rows with '(SCA)' at the SQL level, keep NULLs
        query = """
            SELECT
                alert_id,
                rule_id,
                dismissed_reason,
                dismissed_comment,
                code_snippet
            FROM alerts
            WHERE rule_id IS NULL OR LOWER(rule_id) NOT LIKE '%(sca)%'
        """
        cursor.execute(query)

        # Column names
        columns = [desc[0] for desc in cursor.description]
        print("Columns:", columns)

        # Initialize OpenAI client
        client = get_openai_client(args.api_key)

        # Fetch and process rows
        rows = cursor.fetchall()
        print(f"Total rows fetched (post-SQL filter): {len(rows)}")

        skipped = 0
        analyzed = 0

        for row in rows:
            record = dict(zip(columns, row))
            rule_id_val = str(record.get("rule_id") or "")

            # Defensive Python-side skip in case SQL filter misses anything
            if "(sca)" in rule_id_val.lower():
                skipped += 1
                print(f"[SKIP] alert_id={record.get('alert_id')} rule_id='{rule_id_val}' contains '(SCA)'.")
                continue

            payload = {
                "alert_id": record.get("alert_id"),
                "rule_id": record.get("rule_id"),
                "dismissed_reason": record.get("dismissed_reason"),
                "dismissed_comment": record.get("dismissed_comment"),
                "code_snippet": record.get("code_snippet"),
            }

            result = analyze_with_gpt(client, args.model, payload)

            analyzed += 1
            classification = result.get("classification", "uncertain")
            reasoning = result.get("reasoning", "")
            recommended_action = result.get("recommended_action", "")

            # Print the raw row and analysis summary
            print("Row:", record)
            print(f"Analysis -> classification: {classification}")
            if reasoning:
                print(f"Reasoning: {reasoning}")
            if recommended_action:
                print(f"Recommended action: {recommended_action}")
            print("-" * 60)

        print(f"Done. Analyzed: {analyzed}, Skipped: {skipped}")

    except Exception as e:
        print("Error:", e)
        traceback.print_exc()
    finally:
        try:
            if cursor is not None:
                cursor.close()
        except Exception:
            pass
        try:
            if conn is not None:
                conn.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()