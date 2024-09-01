<h1 align="center">
  <br>
  <a href="https://github.com/vquid0/HTMLI"><h1>HTMLI</h1></a>
  <br>
  XSStrike
  <br>
</h1>

<h4 align="center">Automates HTML injection, HTTP pollution, and XXE vulnerabilities.</h4>

<p align="center">
  <a href="python.org">
    <img src="https://img.shields.io/badge/HTMLI-Python-blue">
  </a>
   <img alt="Static Badge" src="https://img.shields.io/badge/License-GPLv3-yellow">
  </a>
      <img alt="Static Badge" src="https://img.shields.io/badge/Status-Beta-orange">
  </a>
</p>

![HTMLI](https://ibb.co.com/XDpqsYn)

## Features:

- **HTTP Parameter Pollution (HPP)**
- **HTML Injection (HTMLi)**
- **XML External Entity (XXE) Injection**

## Usage

`python htmli.py -u <target_url> [--hpp] [--htmli] [--xxe]`

**Arguments:**

- `-u`, `--url`: The target website URL (required).
- `--hpp`:  Enable HTTP Parameter Pollution testing.
- `--htmli`: Enable HTML Injection testing.
- `--xxe`: Enable XXE Injection testing. 

**Examples:**

- **Test for all vulnerabilities:**
  ```bash
  python web_vulnerability_assassin.py -u "https://example.com" --hpp --htmli --xxe

## Important Notes
Responsibility: Use this tool ethically and responsibly.

Licensed under the GNU GPLv3.
