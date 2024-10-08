<h1 align="center">
<a href="https://github.com/vquid0/HTMLI"><h1>HTMLI</h1></a>
</h1>
<h4 align="center">Automates HTML injection, HTTP Parameter Pollution, and XXE attacks.</h4>

<p align="center">
  <a href="python.org">
    <img src="https://img.shields.io/badge/HTMLI-Python-blue">
  </a>
   <img alt="Static Badge" src="https://img.shields.io/badge/License-GPLv3-yellow">
  </a>
      <img alt="Static Badge" src="https://img.shields.io/badge/Status-Beta-orange">
  </a>
</p>

<br>
<center><img src="https://i.postimg.cc/8cXFcr3Z/HTMLI.png"></center>
<br>

## Features:

- **HTTP Parameter Pollution (HPP)**
- **HTML Injection (HTMLi)**
- **XML External Entity (XXE) Injection**

# Installation
```bash
git clone https://github.com/vquid0/HTMLI
cd HTMLI
pip install -r requirements.txt
```

## Usage

`python htmli.py -u <target_url> [--hpp] [--htmli] [--xxe]`

**Arguments:**

- `-u`, `--url`: The target website URL.
- `--hpp`:  Enable HTTP Parameter Pollution testing.
- `--htmli`: Enable HTML Injection testing.
- `--xxe`: Enable XXE Injection testing. 

**Examples:**

- **Test for all vulnerabilities:**
  ```bash
  python htmli.py -u "https://example.com" --hpp --htmli --xxe

## Important Notes
Use this tool ethically and responsibly.                                                           
This Tool Still In Beta.

Licensed under the GNU GPLv3.
