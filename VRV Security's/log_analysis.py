# import re
# from collections import Counter, defaultdict
# import csv

# # Function to parse log file
# def parse_log_file(file_path):
#     with open(file_path, 'r') as file:
#         logs = file.readlines()
#     return logs

# # Function to count requests per IP address
# def count_requests_per_ip(logs):
#     ip_pattern = r'^(\S+)'
#     ip_counts = Counter(re.match(ip_pattern, log).group(1) for log in logs)
#     return ip_counts.most_common()

# # Function to find the most frequently accessed endpoint
# def most_frequent_endpoint(logs):
#     endpoint_pattern = r'\"(?:GET|POST) (\S+)'
#     endpoints = [re.search(endpoint_pattern, log).group(1) for log in logs if re.search(endpoint_pattern, log)]
#     endpoint_counts = Counter(endpoints)
#     return endpoint_counts.most_common(1)[0]

# # Function to detect suspicious activity (brute force detection)
# def detect_suspicious_activity(logs, threshold=10):
#     failed_login_pattern = r'^(\S+).*\s401\s.*'
#     failed_logins = Counter(re.match(failed_login_pattern, log).group(1) for log in logs if re.match(failed_login_pattern, log))
#     return {ip: count for ip, count in failed_logins.items() if count > threshold}

# # Function to save results to CSV
# def save_results_to_csv(ip_counts, most_accessed_endpoint, suspicious_activity, output_file):
#     with open(output_file, 'w', newline='') as file:
#         writer = csv.writer(file)
        
#         # Requests per IP
#         writer.writerow(["Requests per IP"])
#         writer.writerow(["IP Address", "Request Count"])
#         for ip, count in ip_counts:
#             writer.writerow([ip, count])
        
#         # Most Accessed Endpoint
#         writer.writerow([])
#         writer.writerow(["Most Accessed Endpoint"])
#         writer.writerow(["Endpoint", "Access Count"])
#         writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])
        
#         # Suspicious Activity
#         writer.writerow([])
#         writer.writerow(["Suspicious Activity"])
#         writer.writerow(["IP Address", "Failed Login Count"])
#         for ip, count in suspicious_activity.items():
#             writer.writerow([ip, count])

# # Main function to process the log file and display results
# def main():
#     # File paths
#     log_file_path = 'sample_log_file.txt'
#     output_file = 'log_analysis_results.csv'
    
#     # Parse logs
#     logs = parse_log_file(log_file_path)
    
#     # Count requests per IP
#     ip_counts = count_requests_per_ip(logs)
#     print("Requests per IP Address:")
#     print("IP Address           Request Count")
#     for ip, count in ip_counts:
#         print(f"{ip:20} {count}")
    
#     # Most Frequently Accessed Endpoint
#     most_accessed_endpoint = most_frequent_endpoint(logs)
#     print("\nMost Frequently Accessed Endpoint:")
#     print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    
#     # Detect Suspicious Activity
#     suspicious_activity = detect_suspicious_activity(logs)
#     print("\nSuspicious Activity Detected:")
#     if suspicious_activity:
#         print("IP Address           Failed Login Attempts")
#         for ip, count in suspicious_activity.items():
#             print(f"{ip:20} {count}")
#     else:
#         print("No suspicious activity detected.")
    
#     # Save results to CSV
#     save_results_to_csv(ip_counts, most_accessed_endpoint, suspicious_activity, output_file)
#     print(f"\nResults saved to {output_file}")

# if __name__ == "__main__":
#     main()



import csv
from collections import Counter, defaultdict

# File paths
log_file_path = "sample_log_file.txt"
output_csv_path = "log_analysis_results.csv"

# Threshold for suspicious activity
FAILED_LOGIN_THRESHOLD = 10

def parse_log_file(file_path):
    """Parses the log file and extracts relevant data."""
    requests_per_ip = Counter()
    endpoint_counter = Counter()
    failed_logins = defaultdict(int)
    
    with open(file_path, 'r') as file:
        for line in file:
            parts = line.split()
            
            if len(parts) < 9:
                continue
            
            # Extract IP, HTTP method, endpoint, status code, and optional message
            ip = parts[0]
            method = parts[5].strip('"')
            endpoint = parts[6]
            status_code = parts[8]
            message = " ".join(parts[9:]).strip('"') if len(parts) > 9 else ""
            
            # Count requests per IP
            requests_per_ip[ip] += 1
            
            # Count endpoint accesses
            endpoint_counter[endpoint] += 1
            
            # Count failed logins
            if status_code == "401" or "Invalid credentials" in message:
                failed_logins[ip] += 1
    
    return requests_per_ip, endpoint_counter, failed_logins

def save_results_to_csv(requests_per_ip, most_accessed_endpoint, suspicious_ips, output_file):
    """Saves results to a CSV file."""
    with open(output_file, 'w', newline='') as file:
        writer = csv.writer(file)
        
        # Write Requests per IP
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        writer.writerows(requests_per_ip.items())
        
        # Write Most Accessed Endpoint
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])
        
        # Write Suspicious Activity
        writer.writerow([])
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        writer.writerows(suspicious_ips.items())

def main():
    # Parse the log file
    requests_per_ip, endpoint_counter, failed_logins = parse_log_file(log_file_path)
    
    # Sort Requests per IP
    sorted_requests_per_ip = requests_per_ip.most_common()
    
    # Identify the most accessed endpoint
    most_accessed_endpoint = endpoint_counter.most_common(1)[0] if endpoint_counter else ("None", 0)
    
    # Detect suspicious activity
    suspicious_ips = {ip: count for ip, count in failed_logins.items() if count >= FAILED_LOGIN_THRESHOLD}
    
    # Display results
    print("Requests per IP Address:")
    for ip, count in sorted_requests_per_ip:
        print(f"{ip:<20}{count}")
    
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    
    print("\nSuspicious Activity Detected:")
    if suspicious_ips:
        for ip, count in suspicious_ips.items():
            print(f"{ip:<20}{count}")
    else:
        print("No suspicious activity detected.")
    
    # Save results to CSV
    save_results_to_csv(dict(sorted_requests_per_ip), most_accessed_endpoint, suspicious_ips, output_csv_path)
    print(f"\nResults saved to {output_csv_path}")

if __name__ == "__main__":
    main()
