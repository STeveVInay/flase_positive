False Positive Analyzer — SQL Server + OpenAI GPT

This Python script connects to a SQL Server database, retrieves security alerts from the alerts table, and uses OpenAI’s GPT model (like gpt-4o) to analyze each alert’s code snippet, dismissed reason, and comment.

It helps security teams validate developer-marked “false positives” and identify whether the alert is truly a false positive, a true positive, or secure code.

Here while running the script you need to pass api_key.txt file of your open api key
