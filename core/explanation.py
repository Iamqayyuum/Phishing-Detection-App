def recommendations_for(category: str) -> list[str]:
    if category == "High Risk":
        return [
            "Immediate Action: Avoid accessing this link or submitting personal credentials.",
            "Verification: If this link claims to be from a legitimate organization, verify the communication by visiting their official domain manually via a trusted search engine.",
            "Reporting: Report the message or sender to the relevant authority, especially if received via email, SMS, or messaging platforms."
        ]
    if category == "Suspicious":
        return [
            "Proceed with heightened caution: Carefully inspect the URL structure for domain spoofing or minor character variations.",
            "Integrity Check: Avoid entering sensitive information, such as login credentials or financial details, until you can confirm the website's authenticity through secondary channels."
        ]
    return [
        "Status: No critical phishing indicators were detected, but continue to exercise standard online caution.",
        "Best Practice: If the context of the link is unexpected, verify the source independently before interacting with the content."
    ]