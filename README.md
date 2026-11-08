# siteaudit

A small tool that checks one website for common security mistakes.

You give it a site you own. It looks at the TLS setup, the response headers, the
cookies, the CORS settings and a bunch of files that should not be public. Then
it tells you what it found and gives the site a grade out of 100.

There are two files in here:

- `siteaudit.py` – run it from the terminal
- `siteaudit_gui.py` – same scanner, but in a window

Both use only the Python standard library, so there is nothing to install.

## What you need

Python 3.8 or newer. On Windows that is usually `py -3`, on Mac and Linux `python3`.

## Run it

From the terminal:

```
py -3 siteaudit.py https://example.com --authorized
```

Or open the window:

```
py -3 siteaudit_gui.py
```

`--authorized` means "I own this site or I have written permission to test it".
If you leave it out the tool asks you to confirm. In a script it just stops.

## Things you can add

| flag | what it does |
| --- | --- |
| `--md report.md` | also save the findings as Markdown |
| `--json report.json` | also save them as JSON |
| `--timeout 15` | wait longer for slow servers |
| `--delay 0.5` | slow down between requests |
| `--max-requests 40` | lower the request budget |
| `-v` | print each step while it runs |
| `-q` | no console report, just the files |
| `--version` | print the version |
| `--help` | list everything |

## More than one site

Put the hosts in a text file, one per line:

```
example.com
shop.example.com
```

Then:

```
py -3 siteaudit.py --inventory sites.txt --scope-domain example.com --authorized --md report.md
```

Anything that is not `example.com` or a subdomain of it gets skipped before a
single request goes out. Blank lines and lines starting with `#` are ignored.
The default limit is 25 hosts, and you can raise it with `--limit` up to 200.

## What it looks at

- the certificate, and whether it is close to expiring
- if TLS 1.0 or 1.1 still works
- if HTTP sends you to HTTPS
- HSTS
- Content-Security-Policy
- clickjacking protection
- `X-Content-Type-Options`
- `Referrer-Policy` and `Permissions-Policy`
- COOP and CORP
- cookie flags: `Secure`, `HttpOnly`, `SameSite`
- CORS, with and without credentials
- risky HTTP methods and TRACE
- 25 paths that sometimes leak, like `/.env`, `/.git/config`, `backup.sql`, `terraform.tfstate`
- open directory listings
- password forms on a plain HTTP page
- mixed content
- third party scripts without SRI
- server banners that give away versions
- `robots.txt` and `security.txt`

## What you get

```
==============================================================================
siteaudit — authorized security audit
made by exovmiscoding
target   : https://example.com
started  : 2026-11-08T02:20:26Z
requests : 35 (single host, rate-limited)
==============================================================================

[HIGH] Exposed environment file (.env)
   GET /.env returned 214 bytes matching the expected file content.
   evidence: SECRET_KEY=<redacted>
   fix     : Serve application configuration outside the web root and rotate it.

Summary: 3 high, 4 medium, 3 low, 1 info — grade D (55/100)
```

Every finding has a short explanation, the evidence, and a fix.

## How the grade works

Start at 100 and take off 10 for each high, 4 for each medium, and 1 for each
low. Info findings cost nothing.

| score | grade |
| --- | --- |
| 95+ | A |
| 85+ | B |
| 70+ | C |
| 55+ | D |
| 35+ | E |
| below 35 | F |

## Exit codes

| code | meaning |
| --- | --- |
| 0 | nothing worth fixing |
| 1 | medium findings |
| 2 | high findings |
| 3 | the run failed or you did not confirm |

That makes it easy to drop into a script.

## Limits on purpose

- one host per run, unless you pass a file
- 60 requests per host, at least 0.25 seconds apart
- only GET, OPTIONS and TRACE
- no exploits, no fuzzing, no login attempts
- secrets it finds are redacted in the output

It does not search for sites. You always tell it what to look at.

## The website

`index.html` is the landing page, and `siteaudit.zip` is the download it points
to. Open the page in a browser, or serve the folder with
`py -3 -m http.server`.

## Please

Only run this on sites you own or have permission to test. That is the whole
deal.

made by exovmiscoding
