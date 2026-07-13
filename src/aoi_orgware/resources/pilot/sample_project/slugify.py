def slugify(text: str) -> str:
    """Return a lowercase URL slug."""

    return text.strip().lower().replace(" ", "-")
