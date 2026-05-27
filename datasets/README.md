# Datasets

The following public datasets are used for training and evaluation.
They are NOT committed to this repository due to file size.

## Download Instructions

### 1. CSIC 2010
- URL: https://www.isi.csic.es/dataset/
- File: http_dataset_csic_2010.zip
- ~61,000 labelled HTTP requests (36K normal, 25K malicious)
- Place extracted files in: datasets/csic_2010/

### 2. HTTPParams
- URL: https://github.com/Meatplowz/http-params-dataset
- ~13,000 parameter-level injection samples
- Place in: datasets/httpparams/

### 3. WADE-2022
- URL: https://github.com/ias-tubs/WADE
- Reference: Calvo & Beltran, SECRYPT 2022
- ~40,000+ requests including modern attack variants
- Place in: datasets/wade_2022/

## Usage

DVWA and OWASP Juice Shop are used for LIVE DEMO ONLY.
They do NOT contribute to ML training or offline evaluation.
See demo/README.md for setup instructions.
