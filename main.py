import json
import os
import requests
from typing import List, Dict, Any, Counter
from collections import Counter

# File paths
PACKAGES_FILE = "top_10000_npm_packages.json"
# You can define future paths for vulnerability data here
VULNERABILITY_FILE = "vulnerability_data.json"
VULNERABILITY_DIR = "all"
RESULTS_FILE = "vulnerability_counts.json"

def load_packages() -> List[Dict[str, Any]]:
    """Load the package data from JSON file"""
    try:
        with open(PACKAGES_FILE, 'r') as file:
            packages = json.load(file)
            print(f"Successfully loaded {len(packages)} packages")
            return packages
    except Exception as e:
        print(f"Error loading package file: {e}")
        return []

def extract_package_names(packages: List[Dict[str, Any]]) -> List[str]:
    """Extract just the package names from the full package data"""
    package_names = [package["name"] for package in packages if "name" in package]
    return package_names

def save_package_names(package_names: List[str], output_file: str = "package_names.json"):
    """Save the package names to a separate file for future processing"""
    with open(output_file, 'w') as file:
        json.dump(package_names, file, indent=2)
    print(f"Saved {len(package_names)} package names to {output_file}")

def process_packages_for_vulnerabilities(package_names: List[str]):
    """
    Placeholder for future vulnerability checking functionality
    This function can be expanded to check each package against vulnerability databases
    """
    print(f"Ready to process {len(package_names)} packages for vulnerabilities")
    # Future implementation:
    # 1. Query vulnerability database for each package
    # 2. Analyze results
    # 3. Generate reports
    return

def load_vulnerability_files() -> List[Dict[str, Any]]:
    """Load all vulnerability JSON files from the 'all' directory"""
    vulnerabilities = []
    try:
        if not os.path.isdir(VULNERABILITY_DIR):
            print(f"Error: Directory '{VULNERABILITY_DIR}' not found")
            return vulnerabilities
            
        json_files = [f for f in os.listdir(VULNERABILITY_DIR) if f.endswith('.json')]
        print(f"Found {len(json_files)} vulnerability JSON files")
        
        for json_file in json_files:
            file_path = os.path.join(VULNERABILITY_DIR, json_file)
            try:
                with open(file_path, 'r') as file:
                    vuln_data = json.load(file)
                    vulnerabilities.append(vuln_data)
            except Exception as e:
                print(f"Error loading {json_file}: {e}")
                
        print(f"Successfully loaded {len(vulnerabilities)} vulnerability records")
        return vulnerabilities
    except Exception as e:
        print(f"Error processing vulnerability files: {e}")
        return vulnerabilities

def save_vulnerability_data(vulnerabilities: List[Dict[str, Any]], output_file: str = VULNERABILITY_FILE):
    """Save the combined vulnerability data to a single JSON file"""
    try:
        with open(output_file, 'w') as file:
            json.dump(vulnerabilities, file, indent=2)
        print(f"Saved {len(vulnerabilities)} vulnerability records to {output_file}")
        return True
    except Exception as e:
        print(f"Error saving vulnerability data: {e}")
        return False

def combine_vulnerability_data():
    """Combine all vulnerability JSON files into a single file"""
    print("Loading vulnerability data from JSON files...")
    vulnerabilities = load_vulnerability_files()
    
    if not vulnerabilities:
        print("No vulnerability data found or could be loaded.")
        return False
    
    return save_vulnerability_data(vulnerabilities)

def fetch_download_counts(package_names: List[str]) -> Dict[str, int]:
    """Fetch download counts from NPM API for the past month"""
    print("Fetching download counts from NPM API...")
    download_counts = {}
    total_packages = len(package_names)
    
    for i, package_name in enumerate(package_names, 1):
        if i % 50 == 0:
            print(f"Fetched download counts for {i}/{total_packages} packages")
            
        try:
            url = f"https://api.npmjs.org/downloads/point/last-month/{package_name}"
            response = requests.get(url)
            
            if response.status_code == 200:
                data = response.json()
                if "downloads" in data:
                    download_counts[package_name] = data["downloads"]
            else:
                print(f"Failed to fetch download count for {package_name}: HTTP {response.status_code}")
        except Exception as e:
            print(f"Error fetching download count for {package_name}: {e}")
    
    print(f"Successfully fetched download counts for {len(download_counts)} packages")
    return download_counts

def analyze_vulnerabilities(package_names: List[str]) -> Dict[str, int]:
    """
    Analyze vulnerability files and count how many advisories affect each package
    Returns a dictionary with package names as keys and vulnerability counts as values
    Each advisory is counted only once per package, even if the package appears multiple times
    in the affected array (for different version ranges)
    """
    print("Analyzing vulnerabilities for packages...")
    vulnerability_counts = Counter()
    total_vulnerabilities = 0
    
    # Track which advisories have been counted for which packages
    # This prevents counting the same advisory multiple times for a package
    package_advisories = {}  # format: {package_name: set(advisory_ids)}
    
    # Check if vulnerability data file exists
    if not os.path.exists(VULNERABILITY_FILE):
        print(f"'{VULNERABILITY_FILE}' not found. Please run the combine_vulnerability_data function first.")
        return {}
    
    # Load vulnerability data
    try:
        with open(VULNERABILITY_FILE, 'r') as file:
            vulnerabilities = json.load(file)
    except Exception as e:
        print(f"Error loading vulnerability data: {e}")
        return {}
    
    # Process each vulnerability advisory
    for advisory in vulnerabilities:
        # Get advisory ID
        advisory_id = advisory.get("id", "unknown")
        
        # Check if the advisory has affected packages
        if "affected" in advisory:
            affected_packages = set()
            
            # Each advisory may affect multiple packages
            for affected in advisory["affected"]:
                if "package" in affected and "name" in affected["package"]:
                    package_name = affected["package"]["name"]
                    # Only track if it's in our list of packages
                    if package_name in package_names:
                        affected_packages.add(package_name)
            
            # Count each affected package once per advisory
            for package_name in affected_packages:
                # Initialize tracking set if needed
                if package_name not in package_advisories:
                    package_advisories[package_name] = set()
                
                # Only count if we haven't seen this advisory for this package
                if advisory_id not in package_advisories[package_name]:
                    vulnerability_counts[package_name] += 1
                    package_advisories[package_name].add(advisory_id)
                    total_vulnerabilities += 1
    
    print(f"Found {total_vulnerabilities} unique vulnerabilities affecting {len(vulnerability_counts)} packages")
    return vulnerability_counts

def save_vulnerability_counts(counts: Dict[str, int], download_counts: Dict[str, int] = None, output_file: str = RESULTS_FILE):
    """Save the vulnerability counts and download counts to a JSON file"""
    # Sort counts by number of vulnerabilities (descending)
    sorted_counts = dict(sorted(counts.items(), key=lambda x: x[1], reverse=True))
    
    # Create a result dictionary with individual counts, downloads, and totals
    result = {
        "packages": {},
        "total_vulnerabilities": sum(counts.values()),
        "total_affected_packages": len(counts)
    }
    
    # Add package data with both vulnerability counts and download counts
    for package, vuln_count in sorted_counts.items():
        result["packages"][package] = {
            "vulnerabilities": vuln_count,
            "downloads": download_counts.get(package, 0) if download_counts else 0
        }
    
    try:
        with open(output_file, 'w') as file:
            json.dump(result, file, indent=2)
        print(f"Saved vulnerability counts and download data to {output_file}")
        return True
    except Exception as e:
        print(f"Error saving vulnerability counts: {e}")
        return False

def main():
    # Check if package_names.json exists
    if os.path.exists("package_names.json"):
        print("'package_names.json' already exists. Loading package names...")
        with open("package_names.json", 'r') as file:
            package_names = json.load(file)
        print(f"Loaded {len(package_names)} package names")
    else:
        print("Loading NPM package data...")
        packages = load_packages()
        
        if not packages:
            print("No package data found. Please check the JSON file.")
            return
        
        # Extract just the package names
        package_names = extract_package_names(packages)
        print(f"Extracted {len(package_names)} package names")
        # Save the package names for future use
        save_package_names(package_names)
    
    # Check if vulnerability data file exists
    if os.path.exists(VULNERABILITY_FILE):
        print(f"'{VULNERABILITY_FILE}' already exists. Skipping combining vulnerability data.")
    else:
        print("\nCombining vulnerability data...")
        combine_vulnerability_data()
    
    # Analyze vulnerabilities and generate counts report
    print("\nAnalyzing vulnerabilities for packages...")
    vulnerability_counts = analyze_vulnerabilities(package_names)
    
    if vulnerability_counts:
        # Only fetch download counts for packages with vulnerabilities
        vulnerable_packages = list(vulnerability_counts.keys())
        print(f"\nFetching download counts for {len(vulnerable_packages)} vulnerable packages...")
        download_counts = fetch_download_counts(vulnerable_packages)
        
        # Save results including download counts
        save_vulnerability_counts(vulnerability_counts, download_counts)
        print(f"\nAnalysis complete. Results with download counts saved to {RESULTS_FILE}")
    else:
        print("\nNo vulnerability data could be analyzed. Please check the vulnerability files.")
    
    print("Processing complete.")

if __name__ == "__main__":
    main()