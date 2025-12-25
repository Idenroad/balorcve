# BalorCVE
BalorCVE is a CVE (Common Vulnerabilities and Exposures) manager designed This project is primarily designed to be integrated into the [Balor](https://github.com/idenroad/Balor)

## Key Features

- Search and browse CVEs offline (local database) or online (via NVD API).
- Download and import official NVD JSON files.
- Filtering by keywords, dates, CVSS score, and severity.
- Interactive console interface with rich display (tables, panels).
- French/English bilingual support with automatic language detection.
- Export CVE details to HTML format.

## Installation

```bash
pipx install git+https://github.com/idenroad/balorcve.git
```
## Usage

Run the tool in your console:
```bash
balorcve
```
Follow the menus to switch between offline and online modes.

## Integration

BalorCVE is designed for easy integration into the Balor framework.
## License

MIT License
---

## Useful Links

- [Balor Framework](https://github.com/idenroad/Balor)
- [NVD - National Vulnerability Database](https://nvd.nist.gov/)
