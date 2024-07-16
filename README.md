# virustotal-hash-analyzer
Fetches file hash reports from VirusTotal via API, saving results in JSON and Excel. Handles errors, logs, and offers detailed analysis of scan data.


## Features

- Fetches file hash reports from VirusTotal API.
- Saves results in JSON and Excel formats.
- Handles errors and logs detailed error messages.
- Provides detailed analysis of scan data.

## Requirements

- Python 3.x
- `openpyxl` library
- `requests` library

## Installation

1. Install the required Python libraries:

    ```sh
    pip install openpyxl requests
    ```

2. Clone this repository:

    ```sh
    git clone https://github.com/your-username/virustotal-hash-analyzer.git
    cd virustotal-hash-analyzer
    ```

3. Obtain your VirusTotal API key from [VirusTotal](https://www.virustotal.com/) and replace `'YOUR_VIRUSTOTAL_API_KEY'` in the script.

## Usage

1. Prepare your Excel file `file_hashes.xlsx` with file hashes in the second column.
2. Run the script:

    ```sh
    python hash_analyzer.py
    ```

3. View results in `vt_results.json` and `vt_results.xlsx`.

## License

This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.
