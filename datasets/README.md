# Datasets

Two public datasets are used for training and evaluation. They are NOT
committed to this repository because of file size. build_dataset.py reads
them from this folder and writes data/merged_dataset.csv.

## Download instructions

### 1. CSIC 2010
- URL: https://www.isi.csic.es/dataset/
- Files used: normalTrafficTraining.txt, normalTrafficTest.txt, anomalousTrafficTest.txt
- Place them in: datasets/csic_2010/
- Rows used: 72,000 normal and 25,065 anomalous (97,065 in total)

### 2. HTTPParams
- URL: https://github.com/Meatplowz/http-params-dataset
- File used: payload_full.csv
- Place it in: datasets/httpparams/
- Rows used: 31,067 (11,763 attack and 19,304 benign)

## Merged dataset
- 128,132 rows: 91,304 benign and 36,828 attack
- Split 80/20, stratified, random_state=42 (102,505 train and 25,627 test)

## Known issues
- 259 CSIC attack rows have no usable text: the parser finds only spaces, "/"
  or "/~" and no query or body. The four checked have ordinary headers. Why
  CSIC labels them anomalous was not found out. augment_and_retrain.py drops
  the 215 that fall in the training part.
- Normal two-parameter and short requests are rare in both datasets. The
  synthetic normal requests in augment_and_retrain.py cover this.

## Usage
DVWA and OWASP Juice Shop are used for live demo and replay tests only.
They do NOT contribute to ML training or offline evaluation.
