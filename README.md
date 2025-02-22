# EasyCA

EasyCA is a simple and easy-to-use tool for managing Certificate Authorities (CAs) and generating SSL/TLS certificates. It simplifies the process of creating and managing certificates for your applications and services.

## Features

- Create and manage Certificate Authorities (CAs)
- Generate SSL/TLS certificates
- Easy-to-use command-line interface
- Supports multiple certificate profiles

## Installation

To install EasyCA, clone the repository and run the setup script:

```bash
git clone https://github.com/t11z/EasyCA.git
```

## Usage

```bash
usage: easyca.py [-h] [--country COUNTRY] [--state STATE] [--locality LOCALITY] [--organization ORGANIZATION] [--subject-alt-names SUBJECT_ALT_NAMES] [--days DAYS]
                 [--basedir BASEDIR]
                 [{create-ca,create-csr,sign-csr,show-cert,wizard}] [common_name]

EasyCA - A simple tool for managing CAs and certificates.

positional arguments:
  {create-ca,create-csr,sign-csr,show-cert,wizard}
                        The command to execute. Use 'wizard' for interactive mode.
  common_name           The common name for the CA or CSR.

options:
  -h, --help            show this help message and exit
  --country COUNTRY     The country for the CA or CSR.
  --state STATE         The state for the CA or CSR.
  --locality LOCALITY   The locality for the CA or CSR.
  --organization ORGANIZATION
                        The organization for the CA or CSR.
  --subject-alt-names SUBJECT_ALT_NAMES
                        The subject alternative names for the CSR.
  --days DAYS           The validity period in days for the CA or CSR.
  --basedir BASEDIR     The base directory for storing CA and certificate files.
```

## Contributing

Contributions are welcome! Please open an issue or submit a pull request on GitHub.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.