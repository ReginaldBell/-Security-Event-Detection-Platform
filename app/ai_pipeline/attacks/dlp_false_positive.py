def run():
    # A safe, benign query designed to validate that the DLP scanner does not
    # produce false positives on ordinary text that happens to contain words
    # like "key", "token", or "secret" without matching actual secret patterns.
    return {
        "name": "dlp_false_positive",
        "input": (
            "What is the best way to manage encryption keys in a cloud environment? "
            "I want to understand key rotation policies and token lifecycle management."
        ),
    }
