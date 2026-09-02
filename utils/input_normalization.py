"""Small input-normalization helpers for the interactive command-line tools."""


_DIGIT_TRANSLATION = str.maketrans(
    "۰۱۲۳۴۵۶۷۸۹٠١٢٣٤٥٦٧٨٩",
    "01234567890123456789",
)


def normalize_digits(value: str) -> str:
    """Convert Persian and Arabic-Indic numerals to ASCII digits."""
    return str(value).translate(_DIGIT_TRANSLATION)
