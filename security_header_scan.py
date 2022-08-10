"""A module to retrieve security related HTTP headers looking for missing ones"""
import argparse
import csv
import sys
import warnings
import requests
warnings.filterwarnings('ignore')

SECURITY_HEADERS = ['Strict-Transport-Security', 'X-Content-Type-Options', 'X-Frame-Options',
                    'Referrer-Policy', 'X-Permitted-Cross-Domain-Policies', 'Content-Security-Policy']

def retrieve_headers(target, method='get'):
    """Retrieve the security related headers from the target"""
    sys.stdout.write(f"[+] Retrieving security headers for {target}...")
    sys.stdout.flush()

    missing_headers = []
    session = requests.Session()
    try:
        if method == 'get':
            request = session.get(f"https://{target}/", timeout=5, verify=False)
        elif method == 'head':
            request = session.head(f"https://{target}/", timeout=5, verify=False)
        elif method == 'options':
            request = session.options(f"https://{target}/", timeout=5, verify=False)
        else:
            print(f"Unsupported HTTP method requested: {method}")
            sys.exit()
        headers = request.headers

        for header in SECURITY_HEADERS:
            if header not in headers:
                missing_headers.append(header)

    except Exception as exc:
        print(f"Exception: {exc}")

    sys.stdout.write("Done!\n")
    return missing_headers

def create_output(results, findings, filename, file_format):
    """Output the findings in the specified format"""
    if file_format != 'csv':
        print(f"[-] Error: Only supported output format is CSV: {file_format}")
        sys.exit(1)

    # Sort the findings so we can ensure consistent results
    findings = list(sorted(findings))
    print(results)

    with open(filename, 'w', encoding="utf-8") as csv_file:
        csv_writer = csv.writer(csv_file)

        # Write the Headers
        columns = findings.copy()
        columns.insert(0, 'Host')
        csv_writer.writerow(columns)

        # Write each target's row, sorted by IP Address
        for target in sorted(results):
            # Write this target's row
            row = [target]
            for finding in findings:
                row.append('x') if finding in results[target] else row.append('')
            csv_writer.writerow(row)
    print(f"[+] Successfully wrote missing security related headers to {filename}!")

def main():
    """Parse the arguments and retrieve each target's security related headers"""

    # Parse required arguments to generate the list of targets and output configurations
    parser = argparse.ArgumentParser(
        description='Retrieve the missing security related headers from each host, checking port 443 if not specified')
    parser.add_argument('filename', help="The output filename")
    parser.add_argument('targets',
                    help='comma separated list of targets in host:port form with default port 443')
    parser.add_argument('--format', default='csv',
                        help='The output format to display and save results in, defaults to csv.')
    parser.add_argument('--method', default='get',
                        help='The HTTP method to use to retrieve the headers, defaults to get.')
    args = parser.parse_args()
    output_filename = args.filename
    output_format = args.format
    targets = args.targets.split(',')
    method = args.method

    # Retrieve the missing headers for each target
    results_map = {}
    findings = set()
    for target in targets:
        result = retrieve_headers(target, method)
        findings.update(result)
        results_map[target] = result

    # Output the results to the desired format
    create_output(results_map, findings, output_filename, output_format)


if __name__ == "__main__":
    main()
