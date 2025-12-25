import os

MESSAGES = {
    "fr": {
        "search_online_title": "Recherche CVE en ligne via API NVD",
        "enter_keywords": "Mots-clés (laisser vide pour tous)",
        "enter_end_date": "Date de fin (YYYY-MM-DD)",
        "invalid_date_format": "Format de date invalide",
        "date_range_too_long": "La plage de dates ne peut pas dépasser 120 jours",
        "enter_min_score": "Score minimum (ex: 0.0)",
        "enter_severity": "Sévérité (LOW, MEDIUM, HIGH, CRITICAL) ou vide",
        "invalid_severity": "Sévérité invalide",
        "no_results": "Aucun résultat trouvé",
        "no_results_after_filter": "Aucun résultat trouvé après filtrage",
        "select_cve_index": "Sélectionner un CVE par index, ou 'r' pour revenir",
        "invalid_index": "Index invalide",
        "details_not_found": "Détails non trouvés",
        "saved_html": "Détails CVE sauvegardés en HTML dans",
        "main_menu": "Menu principal",
        "offline_mode": "Mode offline (avec données locales)",
        "online_mode": "Mode online (via API NVD)",
        "quit": "Quitter",
        "choice": "Choix",
        "no_local_data": "Aucune donnée CVE locale trouvée.",
        "download_default_2025": "Voulez-vous télécharger le fichier 2025 par défaut ? (y/n)",
        "manual_download_info": "Vous pouvez télécharger manuellement depuis https://nvd.nist.gov/vuln/data-feeds",
        "interrupted": "Interrompu par l'utilisateur",
    },
    "en": {
        "search_online_title": "Online CVE Search via NVD API",
        "enter_keywords": "Keywords (leave empty for all)",
        "enter_end_date": "End date (YYYY-MM-DD)",
        "invalid_date_format": "Invalid date format",
        "date_range_too_long": "Date range cannot exceed 120 days",
        "enter_min_score": "Minimum score (e.g. 0.0)",
        "enter_severity": "Severity (LOW, MEDIUM, HIGH, CRITICAL) or empty",
        "invalid_severity": "Invalid severity",
        "no_results": "No results found",
        "no_results_after_filter": "No results found after filtering",
        "select_cve_index": "Select a CVE by index, or 'r' to return",
        "invalid_index": "Invalid index",
        "details_not_found": "Details not found",
        "saved_html": "CVE details saved as HTML to",
        "main_menu": "Main menu",
        "offline_mode": "Offline mode (with local data)",
        "online_mode": "Online mode (via NVD API)",
        "quit": "Quit",
        "choice": "Choice",
        "no_local_data": "No local CVE data found.",
        "download_default_2025": "Do you want to download the default 2025 file? (y/n)",
        "manual_download_info": "You can manually download from https://nvd.nist.gov/vuln/data-feeds",
        "interrupted": "Interrupted by user",
    }
}

def get_lang():
    lang = os.getenv("BALORCVE_LANG") or os.getenv("LANG") or "en"
    lang = lang.lower()
    if lang.startswith("fr"):
        return "fr"
    elif lang.startswith("en"):
        return "en"
    else:
        return "en"

LANG = get_lang()

def msg(key):
    return MESSAGES.get(LANG, MESSAGES["en"]).get(key, key)
