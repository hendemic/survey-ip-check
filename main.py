#%% Import libraries
import pandas as pd
from ip_test import check_ips_against_blocklist
import random

#%% Load the survey data
df = pd.read_csv('enter addr of csv file')


# %% Drop first row if qualtrics added an additional row of header information
df = df.drop(index=[0,1])

#%% Check IP address column. Adjust for actual dataset IP Address column name
df.IPAddress.head(10)


#%% IP address check
ip_block_lists = ["https://github.com/X4BNet/lists_vpn/blob/main/output/vpn/ipv4.txt",
                    "https://github.com/X4BNet/lists_vpn/blob/main/output/datacenter/ipv4.txt"]
blocked_ips = check_ips_against_blocklist(df, 'IPAddress', ip_block_lists)

# %% Calculate percentage of IPs that are blocked
blocked_ips_percentage = len(blocked_ips) / len(df)
print(f"Percentage of IPs that are blocked: {blocked_ips_percentage*100:.2f}%")

