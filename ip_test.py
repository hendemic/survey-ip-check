import pandas as pd
import requests
import ipaddress

def check_ips_against_blocklist(df, ip_column, blocklist_urls):
    """
    Check IP addresses in a dataframe against one or more remote IP block lists.
    
    Args:
        df: pandas DataFrame containing IP addresses
        ip_column: name of the column containing IP addresses
        blocklist_urls: URL or list of URLs to IP block lists (raw text format)
    
    Returns:
        pandas DataFrame with rows where IP addresses match any of the block lists
    """
    
    # Convert single URL to list for uniform processing
    if isinstance(blocklist_urls, str):
        blocklist_urls = [blocklist_urls]
    
    # Collect all CIDR ranges from all block lists
    all_cidr_ranges = []
    
    for blocklist_url in blocklist_urls:
        # Convert GitHub URL to raw content URL if needed
        if "github.com" in blocklist_url and "/blob/" in blocklist_url:
            blocklist_url = blocklist_url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
        
        # Fetch the block list
        print(f"Fetching block list from: {blocklist_url}")
        try:
            response = requests.get(blocklist_url)
            response.raise_for_status()
            
            # Parse CIDR ranges from the response
            ranges_from_this_list = 0
            for line in response.text.strip().split('\n'):
                line = line.strip()
                if line and not line.startswith('#'):  # Skip empty lines and comments
                    try:
                        all_cidr_ranges.append(ipaddress.ip_network(line, strict=False))
                        ranges_from_this_list += 1
                    except ValueError:
                        print(f"Skipping invalid CIDR: {line}")
            
            print(f"Loaded {ranges_from_this_list} CIDR ranges from this list")
            
        except Exception as e:
            print(f"Error fetching {blocklist_url}: {e}")
            continue
    
    print(f"Total loaded: {len(all_cidr_ranges)} CIDR ranges from {len(blocklist_urls)} block lists")
    
    # Check each IP address in the dataframe
    matching_rows = []
    
    for idx, row in df.iterrows():
        ip_str = str(row[ip_column]).strip()
        if not ip_str or ip_str.lower() in ['nan', 'none', '']:
            continue
            
        try:
            ip_addr = ipaddress.ip_address(ip_str)
            
            # Check if this IP is in any of the CIDR ranges
            for cidr_range in all_cidr_ranges:
                if ip_addr in cidr_range:
                    matching_rows.append(idx)
                    print(f"Match found: {ip_str} in {cidr_range}")
                    break
                    
        except ValueError:
            print(f"Skipping invalid IP: {ip_str}")
    
    # Return dataframe with matching rows
    if matching_rows:
        result_df = df.loc[matching_rows].copy()
        print(f"Found {len(result_df)} matching IP addresses")
        return result_df
    else:
        print("No matching IP addresses found")
        return pd.DataFrame(columns=df.columns)



