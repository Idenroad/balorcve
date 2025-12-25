import os
import json
import sqlite3
import gzip
import shutil
import requests
from datetime import datetime, timedelta
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt
from rich.panel import Panel
from rich.text import Text
import html

from .i18n import msg  # Gestion i18n pour offline

DATA_DIR = "/opt/balorsh/data/balorcve"
DOWNLOAD_DIR = os.path.join(DATA_DIR, "cve-download")
CVE_SAVE_DIR = os.path.join(DATA_DIR, "cve")
DB_PATH = os.path.join(DATA_DIR, "cve.db")

NVD_BASE_URL = "https://nvd.nist.gov/feeds/json/cve/2.0"
YEARS = [2020, 2021, 2022, 2023, 2024, 2025]

console = Console()

# === UTILS ===

def ensure_dirs():
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)
    os.makedirs(CVE_SAVE_DIR, exist_ok=True)

def download_cve_file(url, dest_path):
    console.print(msg("download_start").format(url=url))
    try:
        r = requests.get(url, stream=True, timeout=60)
        r.raise_for_status()
        with open(dest_path + ".tmp", "wb") as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)
        os.rename(dest_path + ".tmp", dest_path)
        console.print(msg("download_success").format(path=dest_path))
        return True
    except Exception as e:
        console.print(msg("download_fail").format(error=e))
        return False

def decompress_gz(src_path, dest_path):
    console.print(msg("decompress_start").format(path=src_path))
    try:
        with gzip.open(src_path, 'rt', encoding='utf-8') as f_in, open(dest_path, 'w', encoding='utf-8') as f_out:
            shutil.copyfileobj(f_in, f_out)
        console.print(msg("decompress_success").format(path=dest_path))
        return True
    except Exception as e:
        console.print(msg("decompress_fail").format(error=e))
        return False

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS cve (
            id TEXT PRIMARY KEY,
            description TEXT,
            baseScore REAL,
            baseSeverity TEXT,
            published TEXT,
            lastModified TEXT,
            json TEXT
        )
    ''')
    conn.commit()
    return conn

def import_cve_json(json_path, conn):
    console.print(msg("import_start").format(path=json_path))
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    c = conn.cursor()
    count = 0
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue
        descs = cve.get("descriptions", [])
        desc = next((d["value"] for d in descs if d["lang"] == "en"), "")
        metrics = cve.get("metrics", {})
        baseScore = None
        baseSeverity = None
        cvss31 = metrics.get("cvssMetricV31")
        if cvss31 and len(cvss31) > 0:
            baseScore = cvss31[0].get("cvssData", {}).get("baseScore")
            baseSeverity = cvss31[0].get("cvssData", {}).get("baseSeverity")
        published = cve.get("published")
        lastModified = cve.get("lastModified")
        json_str = json.dumps(cve)
        try:
            c.execute('''
                INSERT OR REPLACE INTO cve (id, description, baseScore, baseSeverity, published, lastModified, json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (cve_id, desc, baseScore, baseSeverity, published, lastModified, json_str))
            count += 1
        except Exception as e:
            console.print(msg("db_insert_error").format(cve_id=cve_id, error=e))
    conn.commit()
    console.print(msg("import_success").format(count=count))

# === SEARCH & DISPLAY ===

def list_downloaded_files():
    files = []
    for f in os.listdir(DOWNLOAD_DIR):
        if f.endswith(".json"):
            files.append(f)
    return sorted(files)

def search_cve(conn, keywords="", year=None, min_score=0.0, severity=None):
    c = conn.cursor()
    query = "SELECT id, description, baseScore, baseSeverity FROM cve WHERE 1=1"
    params = []
    if keywords:
        query += " AND description LIKE ?"
        params.append(f"%{keywords}%")
    if year:
        query += " AND published LIKE ?"
        params.append(f"{year}-%")
    if min_score:
        query += " AND baseScore >= ?"
        params.append(min_score)
    if severity:
        query += " AND baseSeverity = ?"
        params.append(severity.upper())
    query += " ORDER BY baseScore DESC NULLS LAST"
    c.execute(query, params)
    return c.fetchall()

def display_cve_table(results):
    table = Table(title=msg("search_results_title"))
    table.add_column(msg("index"), style="cyan", no_wrap=True)
    table.add_column(msg("cve_id"), style="magenta")
    table.add_column(msg("description"), style="white")
    table.add_column(msg("score"), style="green")
    table.add_column(msg("severity"), style="red")
    for i, (cve_id, desc, score, sev) in enumerate(results, 1):
        desc_short = desc if len(desc) < 60 else desc[:57] + "..."
        score_str = f"{score:.1f}" if score is not None else msg("na")
        sev_str = sev if sev else msg("na")
        table.add_row(str(i), cve_id, desc_short, score_str, sev_str)
    console.print(table)

def format_cve_console(cve_json):
    cve_id = cve_json.get("id", msg("na"))
    descs = cve_json.get("descriptions", [])
    desc = next((d["value"] for d in descs if d["lang"] == "en"), msg("no_description"))
    metrics = cve_json.get("metrics", {})
    baseScore = None
    baseSeverity = None
    cvss31 = metrics.get("cvssMetricV31")
    if cvss31 and len(cvss31) > 0:
        baseScore = cvss31[0].get("cvssData", {}).get("baseScore")
        baseSeverity = cvss31[0].get("cvssData", {}).get("baseSeverity")
    published = cve_json.get("published", msg("na"))
    lastModified = cve_json.get("lastModified", msg("na"))
    references = cve_json.get("references", [])

    text = Text()
    text.append(f"{msg('cve_id')}: {cve_id}\n", style="bold magenta")
    text.append(f"{msg('description')}:\n{desc}\n\n")
    text.append(f"{msg('score')}: {baseScore if baseScore is not None else msg('na')}\n", style="green")
    text.append(f"{msg('severity')}: {baseSeverity if baseSeverity else msg('na')}\n", style="red")
    text.append(f"{msg('published')}: {published}\n")
    text.append(f"{msg('last_modified')}: {lastModified}\n\n")
    if references:
        text.append(f"{msg('references')}:\n", style="bold underline")
        for ref in references:
            url = ref.get("url", "")
            source = ref.get("source", "")
            text.append(f"- {source}: {url}\n", style="blue underline")
    else:
        text.append(f"{msg('no_references')}\n")

    console.print(Panel(text, title=f"{msg('cve_details')}: {cve_id}", width=100))

def save_cve_html(cve_json, filepath):
    cve_id = cve_json.get("id", msg("na"))
    descs = cve_json.get("descriptions", [])
    desc = next((d["value"] for d in descs if d["lang"] == "en"), msg("no_description"))
    metrics = cve_json.get("metrics", {})
    baseScore = None
    baseSeverity = None
    cvss31 = metrics.get("cvssMetricV31")
    if cvss31 and len(cvss31) > 0:
        baseScore = cvss31[0].get("cvssData", {}).get("baseScore")
        baseSeverity = cvss31[0].get("cvssData", {}).get("baseSeverity")
    published = cve_json.get("published", msg("na"))
    lastModified = cve_json.get("lastModified", msg("na"))
    references = cve_json.get("references", [])

    desc_html = html.escape(desc).replace("\n", "<br>")
    refs_html = ""
    for ref in references:
        url = html.escape(ref.get("url", ""))
        source = html.escape(ref.get("source", ""))
        refs_html += f'<li><a href="{url}" target="_blank">{source}</a></li>\n'

    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8" />
        <title>{cve_id} - {msg('cve_details')}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            h1 {{ color: #800000; }}
            .score {{ color: green; font-weight: bold; }}
            .severity {{ color: red; font-weight: bold; }}
            ul {{ list-style-type: none; padding-left: 0; }}
            a {{ text-decoration: none; color: #0066cc; }}
            a:hover {{ text-decoration: underline; }}
        </style>
    </head>
    <body>
        <h1>{cve_id}</h1>
        <p><strong>{msg('description')}:</strong><br>{desc_html}</p>
        <p><strong>{msg('score')}:</strong> <span class="score">{baseScore if baseScore is not None else msg('na')}</span></p>
        <p><strong>{msg('severity')}:</strong> <span class="severity">{baseSeverity if baseSeverity else msg('na')}</span></p>
        <p><strong>{msg('published')}:</strong> {published}</p>
        <p><strong>{msg('last_modified')}:</strong> {lastModified}</p>
        <h2>{msg('references')}</h2>
        <ul>
            {refs_html if refs_html else f'<li>{msg("no_references")}</li>'}
        </ul>
    </body>
    </html>
    """

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html_content)

# === MENUS ===

def offline_menu(conn):
    while True:
        console.print(f"\n[bold]{msg('offline_menu_title')}[/bold]")
        console.print(f"1) {msg('download_cve_year')}")
        console.print(f"2) {msg('download_cve_modified')}")
        console.print(f"3) {msg('redownload_current_year')}")
        console.print(f"4) {msg('search_cve')}")
        console.print(f"5) {msg('quit')}")
        choice = Prompt.ask(msg("choice"), choices=["1","2","3","4","5"])
        if choice == "1":
            year = Prompt.ask(msg("enter_year").format(start=YEARS[0], end=YEARS[-1]), default=str(YEARS[-1]))
            if not year.isdigit() or int(year) not in YEARS:
                console.print(msg("invalid_year"))
                continue
            url = f"{NVD_BASE_URL}/nvdcve-2.0-{year}.json.gz"
            gz_path = os.path.join(DOWNLOAD_DIR, f"nvdcve-2.0-{year}.json.gz")
            json_path = os.path.join(DOWNLOAD_DIR, f"nvdcve-2.0-{year}.json")
            if download_cve_file(url, gz_path):
                decompress_gz(gz_path, json_path)
                import_cve_json(json_path, conn)
        elif choice == "2":
            url = f"{NVD_BASE_URL}/nvdcve-2.0-modified.json.gz"
            gz_path = os.path.join(DOWNLOAD_DIR, "nvdcve-2.0-modified.json.gz")
            json_path = os.path.join(DOWNLOAD_DIR, "nvdcve-2.0-modified.json")
            if os.path.exists(gz_path):
                os.remove(gz_path)
            if os.path.exists(json_path):
                os.remove(json_path)
            if download_cve_file(url, gz_path):
                decompress_gz(gz_path, json_path)
                import_cve_json(json_path, conn)
        elif choice == "3":
            year = str(datetime.now().year)
            url = f"{NVD_BASE_URL}/nvdcve-2.0-{year}.json.gz"
            gz_path = os.path.join(DOWNLOAD_DIR, f"nvdcve-2.0-{year}.json.gz")
            json_path = os.path.join(DOWNLOAD_DIR, f"nvdcve-2.0-{year}.json")
            if download_cve_file(url, gz_path):
                decompress_gz(gz_path, json_path)
                import_cve_json(json_path, conn)
        elif choice == "4":
            keywords = Prompt.ask(msg("enter_keywords"))
            year = Prompt.ask(msg("enter_year_optional"), default="")
            year = int(year) if year.isdigit() else None
            min_score = Prompt.ask(msg("enter_min_score"), default="0.0")
            try:
                min_score = float(min_score)
            except:
                min_score = 0.0
            severity = Prompt.ask(msg("enter_severity"), default="").upper()
            if severity not in ["LOW", "MEDIUM", "HIGH", "CRITICAL", ""]:
                console.print(msg("invalid_severity"))
                severity = None
            else:
                severity = severity if severity else None
            results = search_cve(conn, keywords, year, min_score, severity)
            if not results:
                console.print(msg("no_results"))
                continue
            display_cve_table(results)
            while True:
                sel = Prompt.ask(msg("select_cve_index"), default="r")
                if sel.lower() == "r":
                    break
                if not sel.isdigit() or int(sel) < 1 or int(sel) > len(results):
                    console.print(msg("invalid_index"))
                    continue
                cve_id = results[int(sel)-1][0]
                show_cve_details(conn, cve_id)
        else:
            break

# === ONLINE PART  ===

def online_search():
    console.print(msg("online_search_title"))
    keywords = Prompt.ask(msg("enter_keywords"))
    end_date_str = Prompt.ask(msg("enter_end_date")), default=datetime.now().strftime("%Y-%m-%d"))

    # Validation et conversion
    try:
        end_date = datetime.strptime(end_date_str, "%Y-%m-%d")
    except ValueError:
        console.print("[red]Format de date invalide[/red]")
        return

    start_date = end_date - timedelta(days=120)
    min_score = Prompt.ask(msg("enter_min_score"), default="0.0")
    try:
        min_score = float(min_score)
    except:
        min_score = 0.0

    severity = Prompt.ask(msg("enter_severity"), default="").upper()
    if severity not in ["LOW", "MEDIUM", "HIGH", "CRITICAL", ""]:
        console.print(msg("invalid_severity"))
        severity = None
    else:
        severity = severity if severity else None

    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {}
    if keywords:
        params["keywordSearch"] = keywords
    params["pubStartDate"] = start_date.strftime("%Y-%m-%dT%H:%M:%S")
    params["pubEndDate"] = end_date.strftime("%Y-%m-%dT%H:%M:%S")
    if severity:
        params["cvssV3Severity"] = severity

    try:
        r = requests.get(base_url, params=params, timeout=30)
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        console.print(f"[red]Erreur API: {e}[/red]")
        return

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        console.print("[yellow]Aucun résultat trouvé[/yellow]")
        return

    results = []
    for item in vulns:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "N/A")
        descs = cve.get("descriptions", [])
        desc = next((d["value"] for d in descs if d["lang"] == "en"), "")
        metrics = cve.get("metrics", {})
        baseScore = None
        baseSeverity = None
        cvss31 = metrics.get("cvssMetricV31")
        if cvss31 and len(cvss31) > 0:
            baseScore = cvss31[0].get("cvssData", {}).get("baseScore")
            baseSeverity = cvss31[0].get("cvssData", {}).get("baseSeverity")
        # Filtrage local
        if baseScore is not None and baseScore < min_score:
            continue
        if severity and baseSeverity != severity:
            continue
        results.append((cve_id, desc, baseScore, baseSeverity))

    if not results:
        console.print("[yellow]Aucun résultat trouvé après filtrage[/yellow]")
        return

    display_cve_table(results)

    while True:
        sel = Prompt.ask(msg("select_cve_index"))
        if sel.lower() == "r":
            break
        if not sel.isdigit() or int(sel) < 1 or int(sel) > len(results):
            console.print(msg("invalid_index"))
            continue
        cve_id = results[int(sel)-1][0]
        cve_full = next((item.get("cve") for item in vulns if item.get("cve", {}).get("id") == cve_id), None)
        if cve_full:
            format_cve_console(cve_full)
            save_path_html = os.path.join(CVE_SAVE_DIR, f"{cve_id}.html")
            save_cve_html(cve_full, save_path_html)
            console.print(msg("html_saved").format(path=save_path_html))
        else:
            console.print(msg("details_not_found"))

def show_cve_details(conn, cve_id):
    c = conn.cursor()
    c.execute("SELECT json FROM cve WHERE id = ?", (cve_id,))
    row = c.fetchone()
    if not row:
        console.print(msg("cve_not_found").format(cve_id=cve_id))
        return
    cve_json = json.loads(row[0])

    format_cve_console(cve_json)

    save_path_html = os.path.join(CVE_SAVE_DIR, f"{cve_id}.html")
    save_cve_html(cve_json, save_path_html)
    console.print(msg("html_saved").format(path=save_path_html))
