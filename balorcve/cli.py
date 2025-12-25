from rich.console import Console
from rich.prompt import Prompt
from .core import *
from .i18n import msg

console = Console()

def main():
    ensure_dirs()
    conn = init_db()

    has_data = any(f.endswith(".json") for f in os.listdir(DOWNLOAD_DIR))
    if not has_data:
        console.print(msg("no_local_data"))
        choice = Prompt.ask(msg("download_default_2025"), choices=["y","n"])
        if choice == "y":
            url = f"{NVD_BASE_URL}/nvdcve-2.0-2025.json.gz"
            gz_path = os.path.join(DOWNLOAD_DIR, "nvdcve-2.0-2025.json.gz")
            json_path = os.path.join(DOWNLOAD_DIR, "nvdcve-2.0-2025.json")
            if download_cve_file(url, gz_path):
                decompress_gz(gz_path, json_path)
                import_cve_json(json_path, conn)
        else:
            console.print(msg("manual_download_info"))

    while True:
        console.print(f"\n[bold]{msg('main_menu_title')}[/bold]")
        console.print(f"1) {msg('offline_mode')}")
        console.print(f"2) {msg('online_mode')}")
        console.print(f"3) {msg('quit')}")
        choice = Prompt.ask(msg("choice"), choices=["1","2","3"])
        if choice == "1":
            offline_menu(conn)
        elif choice == "2":
            online_search()
        else:
            break

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print(msg("interrupted"))
