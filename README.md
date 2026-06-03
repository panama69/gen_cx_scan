# gen_cx_scan

A small Python helper script to extract Maven Group IDs from a Docker image using Syft and build a Checkmarx One container scan command.

## Usage

Run the script with the required arguments:

```bash
python3 gen_cx_scan.py --image <docker-image> --project <project-name> --folders <path1> [<path2> ...]
```

### Required options

- `--image` : The Docker image to scan (for example `apache/kafka:latest`).
- `--project` : The Checkmarx One project name.
- `--folders` : One or more target folders inside the container to inspect, such as `/opt/kafka/libs/`.

### Optional options

- `--branch` : The branch name for Checkmarx One. Default is `main`.
- `--cx-path` : Path to the Checkmarx One executable or directory containing the `cx` executable. Default is `./cx`.
- `--dry-run` : Print the generated `cx` command without executing it.
- `--verbose` : Show detailed step-by-step execution and debug output.

## Prerequisites

The script requires:

- Python 3
- Syft

### Install on macOS

```bash
brew install python syft
```

### Install on Windows

Using PowerShell with Chocolatey:

```powershell
choco install python
choco install syft
```

Or using pip if Python is already installed:

```powershell
python -m pip install syft
```

## What it does

1. Runs `syft scan <image> -o json` to inspect the image contents.
2. Parses the Syft JSON output to extract Maven Group IDs from artifacts located in the specified folder(s).
3. Builds a Checkmarx One `cx scan create` command with the extracted package filter.
4. Prints the generated `cx` command.
5. Executes it unless `--dry-run` is provided.

## Example

Dry run only:

```bash
python3 gen_cx_scan.py --image apache/kafka:latest --project myproject --folders /opt/kafka/libs/ --dry-run
```

Execute the scan:

```bash
python3 gen_cx_scan.py --image apache/kafka:latest --project myproject --folders /opt/kafka/libs/
```

Below is how you would execute the cli without the package filter
```
./cx scan create --project-name tomcat --branch latest --scan-types container-security -s . --containers-local-resolution --container-images "library/tomcat:latest"
```
This is what it would look like with the package filter
```
./cx scan create --project-name tomcat -s . --scan-types container-security --container-images library/tomcat:latest --branch last --containers-package-filter '^commons\-daemon.*,^org\.apache\.taglibs.*,^org\.apache\.tomcat.*'
```
This python script finds all the packages in the supplied folder and builds the --containers-package-filter dynamically for you and then executes the cli command. Visit Checkmarx documentation for more information on the [Checkmarx cli commands](https://docs.checkmarx.com/en/34965-346278-container-security-filter-usage.html#UUID-e04497ab-6c6f-6f15-dfd1-6a414a17475f_section-idm234794057407335)
