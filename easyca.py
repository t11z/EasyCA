#!/usr/bin/env python3
import os
import subprocess
import argparse
import shlex
import sys

def run_command(command):
    """Executes a shell command and returns the output."""
    result = subprocess.run(shlex.split(command), capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error: {result.stderr}")
        exit(1)
    return result.stdout.strip()

def get_cas(args):
    """Returns a list of all available CAs (root and sub-CAs)."""
    if not os.path.exists(f"{args.basedir}/ca"):
        os.makedirs(f"{args.basedir}/ca")
    return [d for d in os.listdir(f"{args.basedir}/ca") if os.path.isdir(os.path.join(f"{args.basedir}/ca", d))]

def get_root_ca(args):
    """Finds the root CA based on self-signed certificates."""
    for ca in get_cas(args):
        cert_path = f"{args.basedir}/ca/{ca}/ca.crt"
        if os.path.exists(cert_path):
            issuer_hash = run_command(f'openssl x509 -in "{cert_path}" -noout -issuer_hash')
            subject_hash = run_command(f'openssl x509 -in "{cert_path}" -noout -subject_hash')
            if issuer_hash == subject_hash:  # Root CA is self-signed
                return ca
    return None

def is_sub_ca(common_name, args):
  """Checks if a CA is a sub-CA based on the issuer field in the certificate."""
  cert_path = f"{args.basedir}/ca/{common_name}/ca.crt"
  if not os.path.exists(cert_path):
    raise FileNotFoundError(f"Certificate for {common_name} not found.")
  
  basic_constraints = run_command(f'openssl x509 -in "{cert_path}" -noout -text | grep "CA:TRUE"')
  if not basic_constraints:
    raise ValueError(f"The certificate for {common_name} is not a CA.")
  
  issuer_hash = run_command(f'openssl x509 -in "{cert_path}" -noout -issuer_hash')
  root_ca = get_root_ca(args.basedir)
  if root_ca:
    root_cert_path = f"{args.basedir}/ca/{root_ca}/ca.crt"
    root_subject_hash = run_command(f'openssl x509 -in "{root_cert_path}" -noout -subject_hash')
    return issuer_hash != root_subject_hash
  
  return False

def create_ca(common_name, country, state, locality, organization, days, basedir):
    """Creates a root CA with custom parameters."""
    os.makedirs(f"{basedir}/ca/{common_name}", exist_ok=True)
    print(f"Creating CA '{common_name}'...")
    subj = f'/C={country}/ST={state}/L={locality}/O={organization}/CN={common_name}'
    run_command(f'openssl req -x509 -newkey rsa:4096 -keyout "{basedir}/ca/{common_name}/ca.key" -out "{basedir}/ca/{common_name}/ca.crt" -days {days} -nodes -subj "{subj}"')
    print(f"CA {common_name} has been created.")

def create_csr(common_name, subject_alt_names, country, state, locality, organization, args=None):
    """Creates a CSR for host or sub-CA certificates."""
    print(f"Creating CSR for '{common_name}'...")
    os.makedirs(f"{args.basedir}/csr", exist_ok=True)
    subj = f'/C={country}/ST={state}/L={locality}/O={organization}/CN={common_name}'
    alt_names = ""
    if subject_alt_names:
        alt_names = f'-addext "subjectAltName={",".join([f"DNS:{san.strip()}" for san in subject_alt_names])}"'
    run_command(f'openssl req -new -newkey rsa:2048 -keyout "{args.basedir}/csr/{common_name}.key" -out "{args.basedir}/csr/{common_name}.csr" -nodes -subj "{subj}" {alt_names}')
    print(f"CSR for {common_name} has been created.")

def sign_csr(ca_name, common_name, days=365, args=None):
    """Signs a CSR with the CA and creates the structure for a sub-CA if necessary."""
    print(f"Signing CSR '{common_name}' with CA '{ca_name}'...")
    os.makedirs(f"{args.basedir}/certs", exist_ok=True)
    run_command(f'openssl x509 -req -in "{args.basedir}/csr/{common_name}.csr" -CA "{args.basedir}/ca/{ca_name}/ca.crt" -CAkey "{args.basedir}/ca/{ca_name}/ca.key" -CAcreateserial -out "{args.basedir}/certs/{common_name}.crt" -days {days}')
    print(f"Certificate for {common_name} has been signed.")

def show_cert(common_name, args):
    """Shows the details of a certificate."""
    cert_path = f"{args.basedir}/certs/{common_name}.crt"
    if not os.path.exists(cert_path):
        raise FileNotFoundError(f"Certificate for {common_name} not found.")
    print(run_command(f'openssl x509 -in "{cert_path}" -noout -text'))

def ask_certificate_details(ca=False):
    """Asks the user for certificate details and returns dictionary with the values."""
    details = {}
    details["common_name"] = input("Enter the common name (CN): ")
    details["country"] = input("Enter the country (C): ")
    details["state"] = input("Enter the state (ST): ")
    details["locality"] = input("Enter the locality (L): ")
    details["organization"] = input("Enter the organization (O): ")
    if ca:
        details["days"] = int(input("Enter the validity period in days: "))
    if not ca:
        details["subject_alt_names"] = input("Enter the subject alternative names (SANs), separated by commas: ")
        details["subject_alt_names"] = details["subject_alt_names"].split(",")

    return details

def main(args=None):
  if args.command == "create-ca":
    create_ca(args.common_name, args.country, args.state, args.locality, args.organization, args.days, args.basedir)
  elif args.command == "create-csr":
    create_csr(args.common_name, args.subject_alt_names, args.country, args.state, args.locality, args.organization)
  elif args.command == "sign-csr":
    sign_csr(args.common_name, args.common_name, args.days)
  elif args.command == "show-cert":
    show_cert(args.common_name)
  else:
    print("Invalid command.")
    parser.print_help()

def wizard(args=None):
    """Guides the user through the process of creating a CA and signing certificates."""
    print("Welcome to the EasyCA wizard!")
    print("This tool will guide you through the process of creating a CA and signing certificates.")
    print("Let's get started...")

    while True:
        root_ca = get_root_ca(args)
        if not root_ca:
            print("No root CA found. Let's create one.")
            details = ask_certificate_details(ca=True)
            create_ca(details["common_name"], details["country"], details["state"], details["locality"], details["organization"], details["days"], args.basedir)
            root_ca = details["common_name"]
        
        print(f"Root CA: {root_ca}")
        print("Available actions:")
        print("1. Create CSR")
        print("2. Sign CSR")
        print("3. Exit")
        action = input("Choose an action: ")

        if action == "1":
            print("Is this CSR for a sub-CA?")
            print("1. Yes")
            print("2. No")
            is_sub_ca = input("Choose an option: ")
            if is_sub_ca == "1":
                details = ask_certificate_details(ca=True)
                create_csr(details["common_name"], [], details["country"], details["state"], details["locality"], details["organization"], args)
                os.makedirs(f"{args.basedir}/ca/{details['common_name']}", exist_ok=True)
                os.rename(f"{args.basedir}/csr/{details['common_name']}.key", f"{args.basedir}/ca/{details['common_name']}/ca.key")
                csr = f"{details['common_name']}.csr"
                print("Choose Signing CA:")
                cas = get_cas(args)
                for i, ca in enumerate(cas):
                    print(f"{i + 1}. {ca}")
                ca_index = int(input("Enter the index of the CA to sign with: ")) - 1
                sign_csr(cas[ca_index], csr.split(".")[0], details["days"], args)
                os.rename(f"{args.basedir}/certs/{details['common_name']}.crt", f"{args.basedir}/ca/{details['common_name']}/ca.crt")
                os.remove(f"{args.basedir}/csr/{details['common_name']}.csr")
            else:
                details = ask_certificate_details()
                create_csr(details["common_name"], details["subject_alt_names"], details["country"], details["state"], details["locality"], details["organization"], args)
        elif action == "2":
            if not os.path.exists(f"{args.basedir}/csr"):
                os.makedirs(f"{args.basedir}/csr")
            csrs = [f for f in os.listdir(f"{args.basedir}/csr") if f.endswith(".csr")]
            if not csrs:
                print("No CSRs found.")
                continue

            print("Choose a CSR to sign:")
            for i, csr in enumerate(csrs):
                print(f"{i + 1}. {csr}")
            csr_index = int(input("Enter the index of the CSR to sign: ")) - 1
            csr = csrs[csr_index]

            print("Choose Signing CA:")
            cas = get_cas(args)
            for i, ca in enumerate(cas):
                print(f"{i + 1}. {ca}")
            ca_index = int(input("Enter the index of the CA to sign with: ")) - 1

            sign_csr(cas[ca_index], csr.replace(".csr", ""), days=365, args=args)
            if not os.path.exists(f"{args.basedir}/keys"):
                os.makedirs(f"{args.basedir}/keys")
            os.rename(f"{args.basedir}/csr/{csr.replace('.csr', '.key')}", f"{args.basedir}/keys/{csr.replace('.csr', '.key')}")
            os.remove(f"{args.basedir}/csr/{details['common_name']}.csr")
        elif action == "3":
            break
        else:
            print("Invalid input.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="EasyCA - A simple tool for managing CAs and certificates.")
    
    parser.add_argument("command", nargs="?", choices=["create-ca", "create-csr", "sign-csr", "show-cert", "wizard"],
                        help="The command to execute. Use 'wizard' for interactive mode.")
    parser.add_argument("common_name", nargs="?", help="The common name for the CA or CSR.")
    
    parser.add_argument("--country", help="The country for the CA or CSR.")
    parser.add_argument("--state", help="The state for the CA or CSR.")
    parser.add_argument("--locality", help="The locality for the CA or CSR.")
    parser.add_argument("--organization", help="The organization for the CA or CSR.")
    parser.add_argument("--subject-alt-names", help="The subject alternative names for the CSR.")
    parser.add_argument("--days", type=int, default=3650, help="The validity period in days for the CA or CSR.")
    parser.add_argument("--basedir", default="./", help="The base directory for storing CA and certificate files.")

    args = parser.parse_args()

    if args.command is None or args.command == "wizard":
        if not args.basedir:
            args.basedir = "./"
        wizard(args)
    else:
        if args.command in ["create-ca", "create-csr", "sign-csr"] and not args.common_name:
            parser.error(f"The '{args.command}' command requires a 'common_name' argument.")
        if args.command == "show-cert" and not args.common_name:
            parser.error(f"The 'show-cert' command requires a 'common_name' argument.")
        
        main(args)