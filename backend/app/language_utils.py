import langdetect
from deep_translator import GoogleTranslator

# Map common langdetect codes to readable names (subset of ISO 639-1)
LANGUAGE_MAP = {
    'en': 'English',
    'ta': 'Tamil',
    'hi': 'Hindi',
    'te': 'Telugu',
    'ml': 'Malayalam',
    'kn': 'Kannada',
    'mr': 'Marathi',
    'gu': 'Gujarati',
    'bn': 'Bengali',
    'ur': 'Urdu',
    'fr': 'French',
    'es': 'Spanish',
    'de': 'German',
    'ru': 'Russian',
    'zh-cn': 'Chinese (Simplified)',
    'zh-tw': 'Chinese (Traditional)',
    'ja': 'Japanese',
    'ko': 'Korean',
    'ar': 'Arabic',
    'pt': 'Portuguese',
    'it': 'Italian',
    'nl': 'Dutch',
}

def detect_and_translate(text: str) -> dict:
    """
    Detects the language of the given text.
    If it's not English, translates it to English.
    Returns a dictionary containing:
      - detected_language_code
      - detected_language_name
      - original_text
      - translated_text (if translated, else None)
    """
    if not text or not text.strip():
        return {
            "detected_language_code": "en",
            "detected_language_name": "English",
            "original_text": text,
            "translated_text": None
        }

    try:
        lang_code = langdetect.detect(text)
    except Exception:
        lang_code = 'en'  # Fallback to English if detection fails

    lang_name = LANGUAGE_MAP.get(lang_code, lang_code.upper())

    if lang_code != 'en':
        try:
            translator = GoogleTranslator(source='auto', target='en')
            translated_text = translator.translate(text)
            return {
                "detected_language_code": lang_code,
                "detected_language_name": lang_name,
                "original_text": text,
                "translated_text": translated_text
            }
        except Exception as e:
            # If translation fails, return original and log/print error
            print(f"[WARN] Translation failed: {e}")
            return {
                "detected_language_code": lang_code,
                "detected_language_name": lang_name,
                "original_text": text,
                "translated_text": None
            }
    
    # Already English
    return {
        "detected_language_code": "en",
        "detected_language_name": "English",
        "original_text": text,
        "translated_text": None
    }
