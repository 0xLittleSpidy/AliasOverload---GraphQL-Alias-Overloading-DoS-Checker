#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import asyncio
import aiohttp
import time
from datetime import datetime
from collections import defaultdict
import sys
from tqdm import tqdm

# Color codes for console output
GREEN = '\033[92m'
RED = '\033[91m'
RESET = '\033[0m'

def generate_query(alias_count):
    """
    Generate a GraphQL query with the specified number of aliases.
    """
    fields = [f'a{i}: __typename' for i in range(alias_count)]
    query = 'query AliasOverloadTest {\n' + '\n'.join(fields) + '\n}'
    return {"query": query, "operationName": "AliasOverloadTest"}

async def request_worker(session, url, data, alias_count, results):
    """
    Send a GraphQL request and record the response details.
    """
    request_start_time = time.time()
    try:
        async with session.post(url, json=data, timeout=aiohttp.ClientTimeout(total=30)) as response:
            response_time = time.time() - request_start_time
            await response.read()
            status = response.status
            if status == 504:
                # Handle 504 Gateway Timeout
                results.append({
                    'url': url,
                    'alias_count': alias_count,
                    'status': '504 Gateway Timeout',
                    'start_time': request_start_time,
                    'end_time': time.time(),
                    'response_time': None,
                    'error': 'Gateway Timeout'
                })
            else:
                # Handle successful requests
                results.append({
                    'url': url,
                    'alias_count': alias_count,
                    'status': status,
                    'start_time': request_start_time,
                    'end_time': time.time(),
                    'response_time': response_time
                })
            if args.debug:
                # Print detailed debug information
                print(f"Request to {url} with {alias_count} aliases")
                print("Request Headers:", json.dumps(data, indent=2))
                print("Response Status:", status)
                print("Response Headers:", dict(response.headers))
                print("Response Body:", await response.text())
                print("-------------------")
    except asyncio.TimeoutError:
        # Handle request timeout
        results.append({
            'url': url,
            'alias_count': alias_count,
            'status': 'Timeout',
            'start_time': request_start_time,
            'end_time': time.time(),
            'response_time': None,
            'error': 'Request timed out'
        })
    except Exception as e:
        # Handle other exceptions
        results.append({
            'url': url,
            'alias_count': alias_count,
            'status': 'error',
            'start_time': request_start_time,
            'end_time': time.time(),
            'response_time': None,
            'error': str(e)
        })

async def main():
    """
    Main function to send requests and collect results.
    """
    urls = set()
    if args.url:
        urls.add(args.url)
    if args.url_file:
        with open(args.url_file, 'r') as f:
            for line in f:
                urls.add(line.strip())
    if not urls:
        print("Error: No URLs provided. Use -u or -uf.")
        sys.exit(1)

    # Configure HTTP client
    connector = aiohttp.TCPConnector(ssl=not args.disable_tls)
    headers = {'User-Agent': args.user_agent}
    if args.header:
        for header in args.header:
            key, value = header.split(':', 1)
            headers[key.strip()] = value.strip()

    results = []
    alias_counts = [args.alias1, args.alias2]  # Use alias1 and alias2
    total_tasks = len(urls) * len(alias_counts)

    # Send requests
    async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
        with tqdm(total=total_tasks, disable=args.debug, desc="Progress") as pbar:
            for url in urls:
                for alias_count in alias_counts:
                    data = generate_query(alias_count)
                    await request_worker(session, url, data, alias_count, results)
                    pbar.update(1)
    return results

def format_timestamp(timestamp):
    """
    Convert raw Unix timestamp to human-readable format.
    """
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S.%f')

def print_results(results, analysis, output_file=None):
    """
    Print and save the results.
    """
    # Sort results by start time
    sorted_results = sorted(results, key=lambda x: x['start_time'])
    lines = []
    analysis_lines = []

    # Add headers
    header = f"Status, URL, Aliases, Start Time, End Time, Response Time"
    lines.append(header)
    analysis_lines.append("\nAnalysis:")

    # Add results
    total_request_time = 0.0  # Initialize as float
    for result in sorted_results:
        url = result['url']
        alias_count = result['alias_count']
        status = result.get('status', 'error')
        start_time = format_timestamp(result.get('start_time', 'N/A'))
        end_time = format_timestamp(result.get('end_time', 'N/A'))
        response_time = result.get('response_time', None)
        
        # Only add to total_request_time if response_time is not None
        if response_time is not None:
            total_request_time += response_time
        
        # Format response time in seconds with 2 decimal places
        formatted_response_time = f"{response_time:.2f}s" if response_time is not None else 'N/A'
        line = f"{status}, {url}, {alias_count}, {start_time}, {end_time}, {formatted_response_time}"
        lines.append(line)

    # Add total request time
    lines.append(f"\nTotal Request Time: {total_request_time:.2f}s")

    # Add analysis
    for line in analysis:
        analysis_lines.append(line)

    # Print to console with colors
    print(f"\n{GREEN}Status{RESET}, URL, {GREEN}Aliases{RESET}, {GREEN}Start Time{RESET}, {GREEN}End Time{RESET}, {GREEN}Response Time{RESET}")
    for result in sorted_results:
        url = result['url']
        alias_count = result['alias_count']
        status = result.get('status', 'error')
        start_time = format_timestamp(result.get('start_time', 'N/A'))
        end_time = format_timestamp(result.get('end_time', 'N/A'))
        response_time = result.get('response_time', None)
        formatted_response_time = f"{response_time:.2f}s" if response_time is not None else 'N/A'
        if status == 200:
            print(f"{GREEN}{status}{RESET}, {url}, {alias_count}, {start_time}, {end_time}, {formatted_response_time}")
        else:
            print(f"{RED}{status}{RESET}, {url}, {alias_count}, {start_time}, {end_time}, {formatted_response_time}")
    print(f"\nTotal Request Time: {total_request_time:.2f}s")
    print("\nAnalysis:")
    for line in analysis:
        print(line)

    # Write to file (no color)
    if output_file:
        with open(output_file, 'w') as f:
            f.write('\n'.join(lines + analysis_lines))

def analyze_dos_possibility(results):
    """
    Analyze results to detect potential DoS vulnerabilities.
    """
    analysis = []
    url_groups = defaultdict(list)
    for result in results:
        url_groups[result['url']].append(result)
    
    for url, reqs in url_groups.items():
        sorted_reqs = sorted(reqs, key=lambda x: x['alias_count'])
        times = []
        alias_counts = []
        for req in sorted_reqs:
            if req['status'] == 200 and req['response_time'] is not None:
                times.append(req['response_time'])
                alias_counts.append(req['alias_count'])
            elif req['status'] == '504 Gateway Timeout':
                # If a 504 error occurs, mark it as a potential DoS vulnerability
                analysis.append(f"{url}: Potential DoS vulnerability detected (504 Gateway Timeout for alias count {req['alias_count']}).")
                continue
        
        if len(times) < 2:
            # Skip analysis if there are not enough successful requests
            if not any('504 Gateway Timeout' in line for line in analysis):
                analysis.append(f"{url}: Not enough successful requests to analyze.")
            continue
        
        # Check if higher alias count has higher response time
        if times[1] > times[0]:
            analysis.append(f"{url}: Potential DoS vulnerability detected (higher alias count has higher response time).")
        else:
            analysis.append(f"{url}: No clear DoS vulnerability detected.")
    return analysis

if __name__ == "__main__":
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description='AliasOverload - GraphQL Alias Overloading DoS Checker')
    parser.add_argument('-u', '--url', help='Single URL')
    parser.add_argument('-uf', '--url-file', help='File containing multiple URLs')
    parser.add_argument('--alias1', type=int, required=True, help='First alias count (e.g., 100)')
    parser.add_argument('--alias2', type=int, required=True, help='Second alias count (e.g., 200)')
    parser.add_argument('-o', '--output', help='Output file to store results')
    parser.add_argument('-t', '--disable-tls', action='store_true', help='Disable TLS verification')
    parser.add_argument('-de', '--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('-p', '--proxy', help='Proxy server address')
    parser.add_argument('-ua', '--user-agent', default='AliasOverload/1.0', help='Custom User-Agent string')
    parser.add_argument('-H', '--header', action='append', help='Add custom headers (e.g., "Authorization: Bearer token")')

    args = parser.parse_args()

    # Run the main function
    results = asyncio.run(main())
    analysis = analyze_dos_possibility(results)

    # Print and save results
    print_results(results, analysis, args.output)
