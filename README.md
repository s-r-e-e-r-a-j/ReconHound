##  ReconHound
ReconHound is a Python-based web reconnaissance tool built for penetration testers, bug bounty hunters, and ethical hackers. It helps identify hidden paths, files, subdomains, query parameters, virtual hosts, and fuzzable endpoints — making it a versatile solution for deep web reconnaissance.

##  Features
- Multi-threaded scanning for high-speed web enumeration

- Supports:

    - Directory and file discovery

    - Subdomain enumeration

    - Virtual host detection via Host header

    - Query parameter fuzzing

    - Fuzzing anywhere in the URL using a custom FUZZ placeholder

- Saves results in JSON format

- Gracefully handles interruptions and saves partial results

## Disclaimer 
ReconHound should be used responsibly and legally. Unauthorized use of this tool to scan or fuzz websites without permission is illegal and unethical.

## Compatibility
- Linux (Debian, RedHat, Arch) 

## Installation
**1. Clone the repository:**
```bash
git clone https://github.com/s-r-e-e-r-a-j/ReconHound.git
```
**2. Navigate to the ReconHound directory:**
```bash
cd ReconHound
```
**3. Install dependencies:**
```bash
pip3 install -r requirements.txt
```
**4. Run the install.py script for install:**
```bash
sudo python3 install.py
```
**Then type `y` for install**

**5. Run the tool**
```bash
reconhound [options]
```
## Command-Line Options by Mode
**dir – Directory & File Enumeration**
| Option               | Description                                                       |
|----------------------|-------------------------------------------------------------------|
| `-u`, `--url`        | Target URL (e.g., `https://example.com`)                          |
| `-w`, `--wordlist`   | Path to directory/file wordlist                                   |
| `-e`, `--extensions` | Comma-separated file extensions (e.g., `.php,.html,.js`)(optional)|
| `-t`, `--threads`    | Number of threads to use (default: 10)(optional)                  |
| `-o`, `--output`     | File to save output results (JSON format,out.json)(optional)      |



**Example:**

```bash
reconhound dir -u https://example.com -w /path/to/wordlist/wordlist.txt -e .php,.html -t 20 -o /path/to/save/dir_results.json
```



**sub – Subdomain Enumeration**

| Option             | Description                                                    |
|--------------------|----------------------------------------------------------------|
| `-d`, `--domain`   | Target domain (e.g., `example.com`)                            |
| `-w`, `--wordlist` | Path to subdomain wordlist                                     |
| `-t`, `--threads`  | Number of threads to use, default(10)(optional)                |
| `-o`, `--output`   | File to save output results (JSON format,out.json)(optional)   |




**Example:**

```bash
reconhound sub -d example.com -w /path/to/wordlist/wordlist.txt -t 30 -o /path/to/save/sub_results.json
```



**vhost – Virtual Host Discovery**

| Option             | Description                                                                     |
|--------------------|---------------------------------------------------------------------------------|
| `-i`, `--ip`       | Target IP address (e.g., `192.0.2.1`)(target website IP )                       |
| `-d`, `--domain`   | Real domain name used in Host header(target website domain)(e.g., "example.com")|
| `-w`, `--wordlist` | Virtual host wordlist (e.g., `admin`, `dev`, `test`)                            |
| `-t`, `--threads`  | Number of threads to use, default:10 (optional)                                 |
| `-o`, `--output`   | File to save output results (JSON format,out.json)(optional)                    |



**Example:**

```bash
reconhound vhost -i 192.0.2.1 --domain example.com -w /path/to/wordlist/wordlist.txt -t 25 -o /path/to/save/vhost_results.json
```



**fuzz – Query Parameter Fuzzing**

| Option             | Description                                                    |
|--------------------|----------------------------------------------------------------|
| `-u`, `--url`      | Target URL with `FUZZ` in the parameter (e.g., `?id=FUZZ`)     |
| `-p`, `--param`    | Parameter name to fuzz (e.g., `id`)                            |
| `-w`, `--wordlist` | Payloads wordlist to inject into the parameter                 |
| `-t`, `--threads`  | Number of threads to use, default:10 (optional)                |
| `-o`, `--output`   | File to save output results (JSON format,out.json)(optional)   |



**Example:**

```bash
reconhound fuzz -u "https://example.com/page.php?id=FUZZ" -p id -w /path/to/wordlist/wordlist.txt -t 20 -o /path/to/save/fuzz_results.json
```

```bash
reconhound fuzz -u "https://example.com/login?username=admin&password=FUZZ" -p password -w /path/to/wordlist/wordlist.txt -t 15 -o /path/to/save/fuzz_results.json
```


**fuzzany – Fuzz Anywhere in URL**

| Option             | Description                                                    |
|--------------------|----------------------------------------------------------------|
| `-u`, `--url`      | URL containing `FUZZ` in path or query (e.g., `/FUZZ/login`)   |
| `-w`, `--wordlist` | Wordlist for replacing `FUZZ`                                  |
| `-t`, `--threads`  | Number of threads to use, default:10(optional)                 |
| `-o`, `--output`   | File to save output results (JSON format,out.json)(optional)   |



**Example:**

```bash
reconhound fuzzany -u "https://example.com/FUZZ/login" -w /path/to/wordlist/wordlist.txt -t 15 -o /path/to/save/fuzzany_results.json
```
```bash
reconhound fuzzany -u "https://example.com?FUZZ=admin" -w /path/to/wordlist/wordlist.txt -t 15 -o /path/to/save/fuzzany_results.json
```

```bash
reconhound fuzzany -u "https://example.com/login?username=admin&password=FUZZ" -w /path/to/wordlist/wordlist.txt -t 15 -o /path/to/save/fuzzany_results.json
```

## Help Menu for Each Mode
**dir mode**
```bash
reconhound dir --help
```
**sub mode**
```bash
reconhound sub --help
```
**vhost mode**
```bash
reconhound vhost --help
```
**fuzz mode**
```bash
reconhound fuzz --help
```
**fuzzany mode**
```bash
reconhound fuzzany --help
```
## Uninstallation

**Run the install.py script**
```bash
sudo python3 install.py
```
**Then type `n` for uninstall**

## License
This project is licensed under the MIT License
