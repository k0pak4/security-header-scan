# security-header-scan
Scan a target list of web servers and report which security related HTTP headers are missing
Supports checking for the following headers:
- Strict-Transport-Security
- X-Frame-Options
- Referrer-Policy
- X-Content-Type-Options
- X-Permitted-Cross-Domain-Policies
- Content-Security-Policy

## Installation
All required libraries are covered in the Python3 standard lib, so cloning this repository should suffice.
    
## Usage

### Positional Arguments

#### filename
The output filename for the resulting data.
    
#### targets
A comma separated list of hosts and ports. If no port is given, port 443 is defaulted

### Optional Arguments

#### format
Supported formats are `csv`. Defaults to `csv`.

## Example Usage
`python3 security_header_scan.py test_scan.csv 192.168.0.231,192.168.10.100:8443 --format csv`

## Contributing    
Contributions for the following features (or others!) are welcome through pull requests:

### Future Features
- Add support for more output file types (e.g. .doc, .xls)
- Add support for both http and https, perhaps simultaneous requests.
- Add support for checking more than the base URL, perhaps incorporating spidering or bruteforcing directories/files
- Add support for checking for misconfigured headers, such as Content-Security-Policies that allow unsafe-inline
