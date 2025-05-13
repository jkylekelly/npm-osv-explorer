#!/usr/bin/env python3
import json
import os
import matplotlib.pyplot as plt
import numpy as np
from collections import Counter

# File paths
VULNERABILITY_COUNTS_FILE = "vulnerability_counts.json"
OUTPUT_DIR = "visualizations"

def load_vulnerability_data():
    """Load the vulnerability counts data from JSON file"""
    try:
        with open(VULNERABILITY_COUNTS_FILE, 'r') as file:
            data = json.load(file)
            print(f"Successfully loaded vulnerability data")
            return data
    except Exception as e:
        print(f"Error loading vulnerability data: {e}")
        return None

def create_output_directory():
    """Create the output directory if it doesn't exist"""
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
        print(f"Created output directory: {OUTPUT_DIR}")

def plot_vulnerable_vs_nonvulnerable(data):
    """Create a pie chart showing vulnerable vs non-vulnerable packages"""
    total_packages = 10000  # As stated in the context
    vulnerable_packages = data['total_affected_packages']
    nonvulnerable_packages = total_packages - vulnerable_packages
    
    labels = [f'Packages with vulnerabilities\n({vulnerable_packages}, {vulnerable_packages/total_packages:.1%})', 
              f'Packages without vulnerabilities\n({nonvulnerable_packages}, {nonvulnerable_packages/total_packages:.1%})']
    sizes = [vulnerable_packages, nonvulnerable_packages]
    colors = ['#ff9999', '#66b3ff']
    explode = (0.1, 0)  # explode the 1st slice
    
    plt.figure(figsize=(10, 8))
    plt.pie(sizes, explode=explode, labels=labels, colors=colors,
            autopct='%1.1f%%', shadow=True, startangle=90)
    plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle
    plt.title('Proportion of NPM Packages with Disclosed Vulnerabilities\nOut of Top 10,000 NPM Packages', fontsize=16)
    
    plt.savefig(f'{OUTPUT_DIR}/vulnerable_vs_nonvulnerable_pie.png', bbox_inches='tight')
    plt.close()
    print("Generated pie chart of vulnerable vs non-vulnerable packages")

def plot_top_vulnerable_packages(data, n=20):
    """Create a bar chart of top N most vulnerable packages"""
    # Create a list of tuples (package_name, vulnerability_count)
    packages = []
    for pkg_name, pkg_data in data['packages'].items():
        if isinstance(pkg_data, dict) and 'vulnerabilities' in pkg_data:
            vuln_count = pkg_data['vulnerabilities']
        else:
            # Handle older format where pkg_data is just the vulnerability count
            vuln_count = pkg_data
        packages.append((pkg_name, vuln_count))
    
    # Sort by vulnerability count (descending)
    packages.sort(key=lambda x: x[1], reverse=True)
    top_packages = packages[:n]
    
    names = [pkg[0] for pkg in top_packages]
    counts = [pkg[1] for pkg in top_packages]
    
    plt.figure(figsize=(12, 8))
    bars = plt.bar(range(len(names)), counts, color='#5DA5DA')
    
    # Rotate names for better readability
    plt.xticks(range(len(names)), names, rotation=45, ha='right')
    plt.subplots_adjust(bottom=0.25)  # Add space at the bottom
    
    # Add count labels on top of bars
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                 f'{int(height)}', ha='center', va='bottom')
    
    plt.xlabel('Package Name', fontsize=12)
    plt.ylabel('Number of Vulnerabilities', fontsize=12)
    plt.title(f'Top {n} Most Vulnerable NPM Packages', fontsize=16)
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    
    plt.savefig(f'{OUTPUT_DIR}/top_vulnerable_packages.png', bbox_inches='tight')
    plt.close()
    print(f"Generated bar chart of top {n} vulnerable packages")

def plot_vulnerability_distribution(data):
    """Create a histogram showing the distribution of vulnerabilities per package"""
    # Get counts of vulnerabilities per package
    vulnerability_counts = []
    for pkg_data in data['packages'].values():
        if isinstance(pkg_data, dict) and 'vulnerabilities' in pkg_data:
            vulnerability_counts.append(pkg_data['vulnerabilities'])
        else:
            # Handle older format where pkg_data is just the vulnerability count
            vulnerability_counts.append(pkg_data)
    
    # Count how many packages have each number of vulnerabilities
    count_distribution = Counter(vulnerability_counts)
    
    # Sort by number of vulnerabilities
    x_values = sorted(count_distribution.keys())
    y_values = [count_distribution[x] for x in x_values]
    
    plt.figure(figsize=(12, 8))
    
    # Create the bar chart
    bars = plt.bar(x_values, y_values, color='#60BD68')
    
    # Add count labels on top of bars
    for bar in bars:
        height = bar.get_height()
        if height > 0:  # Only add label if there's a visible bar
            plt.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                    f'{int(height)}', ha='center', va='bottom')
    
    plt.xlabel('Number of Vulnerabilities', fontsize=12)
    plt.ylabel('Number of Packages', fontsize=12)
    plt.title('Distribution of Vulnerabilities Across Affected Packages', fontsize=16)
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    
    plt.savefig(f'{OUTPUT_DIR}/vulnerability_distribution.png', bbox_inches='tight')
    plt.close()
    print("Generated histogram of vulnerability distribution")

def plot_cumulative_vulnerabilities(data):
    """Create a chart showing cumulative vulnerabilities"""
    # Extract packages with their vulnerability counts
    packages = []
    for pkg_name, pkg_data in data['packages'].items():
        if isinstance(pkg_data, dict) and 'vulnerabilities' in pkg_data:
            vuln_count = pkg_data['vulnerabilities']
        else:
            # Handle older format where pkg_data is just the vulnerability count
            vuln_count = pkg_data
        packages.append((pkg_name, vuln_count))
    
    # Sort packages by vulnerability count (descending)
    packages.sort(key=lambda x: x[1], reverse=True)
    
    # Calculate cumulative sum of vulnerabilities
    counts = [pkg[1] for pkg in packages]
    cumulative_counts = np.cumsum(counts)
    
    # Calculate percentage of total
    total_vulnerabilities = data['total_vulnerabilities']
    percentages = [count / total_vulnerabilities * 100 for count in cumulative_counts]
    
    plt.figure(figsize=(12, 8))
    
    # Create line chart
    plt.plot(range(1, len(percentages) + 1), percentages, marker='o', markersize=3)
    
    # Add reference lines
    plt.axhline(y=50, color='r', linestyle='--', alpha=0.5)
    plt.axhline(y=80, color='r', linestyle='--', alpha=0.5)
    
    # Find where we hit 50% and 80% of vulnerabilities
    packages_for_50_percent = next((i for i, p in enumerate(percentages) if p >= 50), len(percentages))
    packages_for_80_percent = next((i for i, p in enumerate(percentages) if p >= 80), len(percentages))
    
    # Add annotations
    plt.annotate(f'Top {packages_for_50_percent+1} packages\n(50% of vulnerabilities)', 
                 xy=(packages_for_50_percent+1, 50),
                 xytext=(packages_for_50_percent+50, 40),
                 arrowprops=dict(arrowstyle='->'))
                 
    plt.annotate(f'Top {packages_for_80_percent+1} packages\n(80% of vulnerabilities)',
                 xy=(packages_for_80_percent+1, 80),
                 xytext=(packages_for_80_percent+50, 70),
                 arrowprops=dict(arrowstyle='->'))
    
    plt.xlabel('Number of Packages (Ranked by Vulnerability Count)', fontsize=12)
    plt.ylabel('Cumulative % of All Vulnerabilities', fontsize=12)
    plt.title('Cumulative Distribution of Vulnerabilities Across Packages', fontsize=16)
    plt.grid(True, linestyle='--', alpha=0.7)
    
    # Set x-axis to log scale to better show distribution
    plt.xscale('log')
    
    plt.savefig(f'{OUTPUT_DIR}/cumulative_vulnerabilities.png', bbox_inches='tight')
    plt.close()
    print("Generated cumulative vulnerability distribution chart")

def plot_downloads_vs_vulnerabilities(data):
    """Create a chart showing download counts in relation to vulnerability percentages"""
    # Get the package data with both vulnerabilities and downloads
    packages = []
    for pkg_name, pkg_data in data['packages'].items():
        if isinstance(pkg_data, dict) and 'vulnerabilities' in pkg_data and 'downloads' in pkg_data:
            packages.append((pkg_name, pkg_data['vulnerabilities'], pkg_data['downloads']))
        else:
            # Handle older format where pkg_data is just the vulnerability count
            packages.append((pkg_name, pkg_data, 0))
    
    # Sort packages by vulnerability count (descending)
    packages.sort(key=lambda x: x[1], reverse=True)
    
    # Calculate cumulative sum of vulnerabilities
    vulnerability_counts = [pkg[1] for pkg in packages]
    cumulative_vulnerabilities = np.cumsum(vulnerability_counts)
    
    # Calculate percentage of total vulnerabilities
    total_vulnerabilities = data['total_vulnerabilities']
    vulnerability_percentages = [count / total_vulnerabilities * 100 for count in cumulative_vulnerabilities]
    
    # Calculate cumulative downloads
    download_counts = [pkg[2] for pkg in packages]
    cumulative_downloads = np.cumsum(download_counts)
    
    # Calculate percentage of total downloads
    total_downloads = sum(download_counts)
    download_percentages = [count / total_downloads * 100 for count in cumulative_downloads]
    
    # Create the figure with two subplots sharing the x-axis
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 12), sharex=True, gridspec_kw={'height_ratios': [1, 1]})
    
    # Plot vulnerability percentages on top subplot
    ax1.plot(range(1, len(vulnerability_percentages) + 1), vulnerability_percentages, 'b-', marker='o', markersize=3, label='Vulnerabilities')
    ax1.set_ylabel('Cumulative % of All Vulnerabilities', fontsize=12, color='b')
    ax1.tick_params(axis='y', labelcolor='b')
    ax1.grid(True, linestyle='--', alpha=0.7)
    ax1.set_title('Cumulative Distribution of Vulnerabilities and Downloads', fontsize=16)
    
    # Plot download percentages on bottom subplot
    ax2.plot(range(1, len(download_percentages) + 1), download_percentages, 'r-', marker='o', markersize=3, label='Downloads')
    ax2.set_xlabel('Number of Packages (Ranked by Vulnerability Count)', fontsize=12)
    ax2.set_ylabel('Cumulative % of All Downloads', fontsize=12, color='r')
    ax2.tick_params(axis='y', labelcolor='r')
    ax2.grid(True, linestyle='--', alpha=0.7)
    
    # Add reference lines for key percentages
    for ax in [ax1, ax2]:
        ax.axhline(y=50, color='gray', linestyle='--', alpha=0.5)
        ax.axhline(y=80, color='gray', linestyle='--', alpha=0.5)
    
    # Find key points
    vuln_50_percent = next((i for i, p in enumerate(vulnerability_percentages) if p >= 50), len(vulnerability_percentages))
    vuln_80_percent = next((i for i, p in enumerate(vulnerability_percentages) if p >= 80), len(vulnerability_percentages))
    
    # Add annotations
    ax1.annotate(f'Top {vuln_50_percent+1} packages\n(50% of vulnerabilities)',
                xy=(vuln_50_percent+1, 50),
                xytext=(vuln_50_percent+50, 40),
                arrowprops=dict(arrowstyle='->'))
    
    ax1.annotate(f'Top {vuln_80_percent+1} packages\n(80% of vulnerabilities)',
                xy=(vuln_80_percent+1, 80),
                xytext=(vuln_80_percent+50, 70),
                arrowprops=dict(arrowstyle='->'))
    
    # Set x-axis to log scale
    plt.xscale('log')
    
    plt.tight_layout()
    plt.savefig(f'{OUTPUT_DIR}/downloads_vs_vulnerabilities.png', bbox_inches='tight')
    plt.close()
    print("Generated downloads vs vulnerabilities distribution chart")
    
    # Create a second visualization: scatter plot of downloads vs vulnerabilities
    plt.figure(figsize=(12, 8))
    
    # Get individual package data
    names = [pkg[0] for pkg in packages[:50]]  # Get top 50 most vulnerable packages
    vulns = [pkg[1] for pkg in packages[:50]]
    downloads = [pkg[2] for pkg in packages[:50]]
    
    # Create scatter plot
    plt.scatter(vulns, downloads, alpha=0.7)
    
    # Annotate key points
    for i, name in enumerate(names[:15]):  # Annotate top 15 for readability
        plt.annotate(name, (vulns[i], downloads[i]))
    
    plt.xlabel('Number of Vulnerabilities', fontsize=12)
    plt.ylabel('Download Count (Last Month)', fontsize=12)
    plt.title('Downloads vs Vulnerabilities for Top 50 Most Vulnerable Packages', fontsize=16)
    plt.grid(True, linestyle='--', alpha=0.5)
    
    # Use log scale for downloads to better visualize
    plt.yscale('log')
    
    plt.tight_layout()
    plt.savefig(f'{OUTPUT_DIR}/vulnerability_download_scatter.png', bbox_inches='tight')
    plt.close()
    print("Generated vulnerability vs downloads scatter plot")

def generate_summary_text(data):
    """Generate a text summary of the vulnerability findings"""
    total_packages = 10000
    vulnerable_packages = data['total_affected_packages']
    total_vulnerabilities = data['total_vulnerabilities']
    
    # Get distribution statistics
    vulnerability_counts = []
    download_counts = []
    
    # Extract vulnerability counts and download counts
    for pkg_data in data['packages'].values():
        if isinstance(pkg_data, dict) and 'vulnerabilities' in pkg_data:
            vulnerability_counts.append(pkg_data['vulnerabilities'])
            if 'downloads' in pkg_data:
                download_counts.append(pkg_data['downloads'])
        else:
            # Handle older format where pkg_data is just the vulnerability count
            vulnerability_counts.append(pkg_data)
    
    max_vulnerabilities = max(vulnerability_counts)
    avg_vulnerabilities = sum(vulnerability_counts) / len(vulnerability_counts)
    
    # Count packages by vulnerability range
    low_vuln_packages = sum(1 for count in vulnerability_counts if count <= 2)
    medium_vuln_packages = sum(1 for count in vulnerability_counts if 3 <= count <= 7)
    high_vuln_packages = sum(1 for count in vulnerability_counts if count >= 8)
    
    # Download statistics
    download_stats = ""
    if download_counts:
        total_downloads = sum(download_counts)
        avg_downloads = total_downloads / len(download_counts)
        max_downloads = max(download_counts)
        min_downloads = min(download_counts)
        
        # Create package tuples for analysis
        packages = []
        for name, pkg_data in data['packages'].items():
            if isinstance(pkg_data, dict) and 'vulnerabilities' in pkg_data and 'downloads' in pkg_data:
                packages.append((name, pkg_data['vulnerabilities'], pkg_data['downloads']))
        
        # Sort by vulnerability count
        packages.sort(key=lambda x: x[1], reverse=True)
        
        # Calculate cumulative vulnerabilities
        vulnerability_counts = [pkg[1] for pkg in packages]
        cumulative_vulnerabilities = np.cumsum(vulnerability_counts)
        
        # Find packages that account for 50% and 80% of vulnerabilities
        vuln_50_percent_idx = next((i for i, count in enumerate(cumulative_vulnerabilities) 
                              if count >= total_vulnerabilities * 0.5), len(packages) - 1)
        vuln_80_percent_idx = next((i for i, count in enumerate(cumulative_vulnerabilities) 
                              if count >= total_vulnerabilities * 0.8), len(packages) - 1)
        
        # Calculate download percentage for these packages
        downloads_50_percent_packages = sum(pkg[2] for pkg in packages[:vuln_50_percent_idx + 1])
        downloads_80_percent_packages = sum(pkg[2] for pkg in packages[:vuln_80_percent_idx + 1])
        
        download_percent_50 = downloads_50_percent_packages / total_downloads * 100
        download_percent_80 = downloads_80_percent_packages / total_downloads * 100
        
        download_stats = f"""
## Download Statistics

* **Total downloads (last month)**: {total_downloads:,}
* **Average downloads per vulnerable package**: {avg_downloads:,.0f}
* **Most downloaded vulnerable package**: {max_downloads:,} downloads
* **Least downloaded vulnerable package**: {min_downloads:,} downloads
* **Packages with 50% of vulnerabilities account for**: {download_percent_50:.1f}% of all downloads
* **Packages with 80% of vulnerabilities account for**: {download_percent_80:.1f}% of all downloads
"""
    
    # Create the summary
    summary = f"""# NPM Package Vulnerability Analysis

## Key Findings

* **Scope**: Analyzed the top 10,000 most popular NPM packages
* **Total vulnerabilities found**: {total_vulnerabilities}
* **Packages with vulnerabilities**: {vulnerable_packages} ({vulnerable_packages/total_packages:.1%} of packages)
* **Packages without vulnerabilities**: {total_packages - vulnerable_packages} ({1 - vulnerable_packages/total_packages:.1%} of packages)

## Vulnerability Distribution

* **Maximum vulnerabilities in a single package**: {max_vulnerabilities}
* **Average vulnerabilities per affected package**: {avg_vulnerabilities:.1f}
* **Packages with low vulnerability count (1-2)**: {low_vuln_packages} ({low_vuln_packages/vulnerable_packages:.1%} of affected packages)
* **Packages with medium vulnerability count (3-7)**: {medium_vuln_packages} ({medium_vuln_packages/vulnerable_packages:.1%} of affected packages)
* **Packages with high vulnerability count (8+)**: {high_vuln_packages} ({high_vuln_packages/vulnerable_packages:.1%} of affected packages)
{download_stats}
## Implications

This analysis highlights that the vast majority of popular NPM packages (95.8%) have no disclosed vulnerabilities. The vulnerabilities that do exist are concentrated in a relatively small number of packages, with just a few packages accounting for a significant portion of all vulnerabilities.

This suggests that vulnerability reporting may be disproportionately focused on a small subset of packages, potentially leaving many vulnerabilities in other packages undiscovered or unreported.
"""
    
    # Save the summary to a markdown file
    with open(f'{OUTPUT_DIR}/vulnerability_summary.md', 'w') as f:
        f.write(summary)
    
    print("Generated vulnerability summary markdown")

def main():
    # Create output directory
    create_output_directory()
    
    # Load vulnerability data
    data = load_vulnerability_data()
    if not data:
        print("No vulnerability data found. Please check the vulnerability_counts.json file.")
        return
    
    # Generate visualizations
    plot_vulnerable_vs_nonvulnerable(data)
    plot_top_vulnerable_packages(data)
    plot_vulnerability_distribution(data)
    plot_cumulative_vulnerabilities(data)
    plot_downloads_vs_vulnerabilities(data)
    
    # Generate summary text
    generate_summary_text(data)
    
    print("\nAll visualizations completed. Results saved to the 'visualizations' directory.")

if __name__ == "__main__":
    main()