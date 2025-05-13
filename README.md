# NPM OSV Explorer

A tool for downloading, analyzing, and visualizing vulnerability data for NPM packages using the [OSV (Open Source Vulnerabilities)](https://google.github.io/osv.dev/) database.

## Overview

This project enables you to:

1. Process vulnerability data from OSV for npm packages
2. Analyze the top npm packages for security vulnerabilities
3. Generate visualizations and statistics about the vulnerabilities
4. Correlate vulnerability counts with package download statistics

## Setup

### Prerequisites

- Python 3.6+
- pip or pipenv

### Installation

1. Clone this repository:
```bash
git clone https://github.com/jkylekelly/npm-osv-explorer.git
cd npm-osv-explorer
```

2. Install dependencies:
```bash
# Using pipenv
pipenv install

# Or using pip (only two direct dependencies)
pip install matplotlib
pip install requests
```

3. Download the OSV data:
   - Visit [OSV Data Dumps](https://google.github.io/osv.dev/data/#data-dumps)
   - Download the npm ecosystem data
   - Extract the JSON files to the `all` directory in the project root
   
   Alternatively, you can run:
   ```bash
   mkdir -p all
   curl -L https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip -o npm_all.zip
   unzip npm_all.zip -d all/
   rm npm_all.zip
   ```

## Usage

### 1. Process Vulnerability Data

Run the main script to process the vulnerability data:

```bash
python main.py
```

This will:
- Load the top npm packages from `top_10000_npm_packages.json`
- Extract package names
- Combine vulnerability data from the `all/` directory
- Analyze vulnerabilities for each package
- Fetch download counts from npm API
- Save results to `vulnerability_counts.json`

### 2. Generate Visualizations

Run the visualization script to create graphs and charts:

```bash
python visualize_vulnerabilities.py
```

This will generate several visualizations in the `visualizations/` directory:
- Pie chart showing vulnerable vs non-vulnerable packages
- Bar chart of the top most vulnerable packages
- Histogram of vulnerability distribution
- Cumulative distribution of vulnerabilities
- Relationship between downloads and vulnerabilities

A markdown summary of findings will also be generated as `visualizations/vulnerability_summary.md`.

## Data Files

- `top_10000_npm_packages.json`: Input file containing the top npm packages (sourced from [npm-rank](https://github.com/tristan-f-r/npm-rank))
- `package_names.json`: Extracted package names for processing
- `vulnerability_data.json`: Combined vulnerability data from the `all/` directory
- `vulnerability_counts.json`: Analysis results with vulnerability and download counts
- `visualizations/`: Generated charts, graphs, and summary

## Customization

You can modify the code to:
- Change the number of packages to analyze
- Adjust visualization parameters
- Add new types of analyses or visualizations

## License

MIT

## Acknowledgments

- [OSV Project](https://google.github.io/osv.dev/) for providing vulnerability data
- [npm-rank](https://github.com/tristan-f-r/npm-rank) for the top 10,000 npm packages data
- npm API for download statistics